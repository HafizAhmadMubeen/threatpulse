#include "enrich.h"

// clang-format off
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
// clang-format on

#include <memory>
#include <vector>

#include "text.h"

namespace tp {

namespace {

constexpr DWORD kReadChunk = 1024 * 1024;

struct HandleCloser {
    void operator()(HANDLE handle) const {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
};
using UniqueFile = std::unique_ptr<void, HandleCloser>;

// Sharing everything means we never block the program whose image we are reading.
UniqueFile open_for_read(const std::wstring& path) {
    return UniqueFile(CreateFileW(path.c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
}

bool is_valid(const UniqueFile& file) {
    return file && file.get() != INVALID_HANDLE_VALUE;
}

std::wstring to_hex(const BYTE* data, size_t size, const wchar_t* digits) {
    std::wstring text;
    text.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        text.push_back(digits[data[i] >> 4]);
        text.push_back(digits[data[i] & 0x0F]);
    }
    return text;
}

std::optional<std::wstring> sha256_file(const std::wstring& path) {
    const UniqueFile file = open_for_read(path);
    if (!is_valid(file)) return std::nullopt;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return std::nullopt;
    }

    std::optional<std::wstring> result;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0))) {
        std::vector<BYTE> chunk(kReadChunk);
        bool ok = true;
        for (;;) {
            DWORD read = 0;
            // A read error must not look like end of file, or a partial hash would
            // be reported as the file's hash.
            if (!ReadFile(file.get(), chunk.data(), kReadChunk, &read, nullptr)) {
                ok = false;
                break;
            }
            if (read == 0) break;  // end of file
            if (!BCRYPT_SUCCESS(BCryptHashData(hash, chunk.data(), read, 0))) {
                ok = false;
                break;
            }
        }
        BYTE digest[32];
        if (ok && BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
            result = to_hex(digest, sizeof(digest), L"0123456789abcdef");
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return result;
}

CRYPT_PROVIDER_SGNR* find_signer(HANDLE state_data) {
    CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(state_data);
    if (!provider) return nullptr;
    return WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
}

bool satisfies_root_policy(PCCERT_CHAIN_CONTEXT chain, DWORD flags) {
    CERT_CHAIN_POLICY_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    parameters.dwFlags = flags;
    CERT_CHAIN_POLICY_STATUS status{};
    status.cbSize = sizeof(status);
    // TRUE only means the check ran. The verdict is in dwError.
    return CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_MICROSOFT_ROOT, chain, &parameters,
                                            &status) &&
           status.dwError == 0;
}

// Checks the chain's root key, not the signer's display name. Any publisher with a
// trusted certificate could put "Microsoft" in a display name, but only Microsoft
// can chain to a Microsoft root. The flag makes the API check the 2011 application
// root instead of the other Microsoft roots, not as well as them, so both are tried.
bool chains_to_microsoft_root(CRYPT_PROVIDER_SGNR& signer) {
    if (!signer.pChainContext) return false;
    return satisfies_root_policy(signer.pChainContext, 0) ||
           satisfies_root_policy(signer.pChainContext,
                                 MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG);
}

std::optional<std::wstring> signer_name(CRYPT_PROVIDER_SGNR& signer) {
    CRYPT_PROVIDER_CERT* certificate = WTHelperGetProvCertFromChain(&signer, 0);
    if (!certificate || !certificate->pCert) return std::nullopt;

    wchar_t name[256];
    const DWORD length = CertGetNameStringW(certificate->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                            nullptr, name, ARRAYSIZE(name));
    if (length <= 1) return std::nullopt;  // the length includes the terminator
    return std::wstring(name);
}

// Runs WinVerifyTrust and always closes its state. Revocation checks stay off, so
// the agent gives the same answer with no network and never waits on one.
LONG verify(WINTRUST_DATA& data, ImageInfo& info) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwStateAction = WTD_STATEACTION_VERIFY;

    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    if (status == ERROR_SUCCESS) {
        info.is_signed = true;
        if (CRYPT_PROVIDER_SGNR* signer = find_signer(data.hWVTStateData)) {
            info.signer = signer_name(*signer);
            info.microsoft_root = chains_to_microsoft_root(*signer);
        }
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return status;
}

// Signature stored inside the file.
LONG verify_embedded(const std::wstring& path, ImageInfo& info) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    return verify(data, info);
}

// Looks the file's hash up in the Windows catalog store. `algorithm` is null for
// the older SHA-1 catalogs.
bool verify_catalog(const std::wstring& path, const wchar_t* algorithm, ImageInfo& info) {
    const UniqueFile file = open_for_read(path);
    if (!is_valid(file)) return false;

    GUID subsystem = DRIVER_ACTION_VERIFY;
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, &subsystem, algorithm, nullptr, 0)) return false;

    bool verified = false;
    DWORD hash_size = 0;
    CryptCATAdminCalcHashFromFileHandle2(admin, file.get(), &hash_size, nullptr, 0);
    std::vector<BYTE> hash(hash_size);
    if (hash_size != 0 &&
        CryptCATAdminCalcHashFromFileHandle2(admin, file.get(), &hash_size, hash.data(), 0)) {
        HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hash_size, 0, nullptr);
        if (catalog) {
            CATALOG_INFO catalog_info{};
            catalog_info.cbStruct = sizeof(catalog_info);
            if (CryptCATCatalogInfoFromContext(catalog, &catalog_info, 0)) {
                // A catalog stores each member under the uppercase hex of its hash.
                const std::wstring tag = to_hex(hash.data(), hash_size, L"0123456789ABCDEF");

                WINTRUST_CATALOG_INFO member{};
                member.cbStruct = sizeof(member);
                member.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
                member.pcwszMemberTag = tag.c_str();
                member.pcwszMemberFilePath = path.c_str();
                member.hMemberFile = file.get();
                member.pbCalculatedFileHash = hash.data();
                member.cbCalculatedFileHash = hash_size;
                member.hCatAdmin = admin;

                WINTRUST_DATA data{};
                data.dwUnionChoice = WTD_CHOICE_CATALOG;
                data.pCatalog = &member;
                verified = verify(data, info) == ERROR_SUCCESS;
            }
            CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        }
    }
    CryptCATAdminReleaseContext(admin, 0);
    return verified;
}

void check_signature(const std::wstring& path, ImageInfo& info) {
    const LONG status = verify_embedded(path, info);
    if (status == ERROR_SUCCESS) return;

    // Many Windows binaries are signed through a catalog, with no signature in the
    // file, so "no signature" here does not mean unsigned. Any other failure, such
    // as a bad digest, is a real failure and stays signed: false.
    if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        status == TRUST_E_PROVIDER_UNKNOWN) {
        if (!verify_catalog(path, BCRYPT_SHA256_ALGORITHM, info)) {
            verify_catalog(path, nullptr, info);
        }
    }
}

// "System" and "unknown" are placeholders, not files.
bool is_file_path(const std::wstring& image) {
    return (image.size() > 2 && image[1] == L':') || istarts_with(image, L"\\\\");
}

bool read_stamp(const std::wstring& path, uint64_t& size, uint64_t& last_write) {
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    size = (static_cast<uint64_t>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    last_write = (static_cast<uint64_t>(data.ftLastWriteTime.dwHighDateTime) << 32) |
                 data.ftLastWriteTime.dwLowDateTime;
    return true;
}

}  // namespace

const ImageInfo& Enricher::get(const std::wstring& image, bool recheck) {
    std::wstring key = lowercase(image);
    const auto found = cache_.find(key);
    if (found != cache_.end() && !recheck) return found->second;

    uint64_t size = 0;
    uint64_t last_write = 0;
    const bool has_stamp = is_file_path(image) && read_stamp(image, size, last_write);

    if (found != cache_.end()) {
        // A file deleted since it was hashed keeps its last known result.
        const bool unchanged =
            !has_stamp || (found->second.file_size == size && found->second.last_write == last_write);
        if (unchanged) return found->second;
    }

    ImageInfo info;
    info.file_size = size;
    info.last_write = last_write;
    if (is_file_path(image)) {
        info.sha256 = sha256_file(image);
        check_signature(image, info);
    }
    return cache_[std::move(key)] = std::move(info);
}

}  // namespace tp
