/*
* @author Sin0n0me
*
* バイナリエディタで覗いたりIDAで逆アセンブルした結果 wincrypt.h を利用した暗号化してる?
*
* 以下のような流れっぽいのでキーを同じ手順で設定すればflag.encの中身をCryptDecrypt()で復号できそう
* 1. flagファイルから暗号化前データ読み取り
* 2. seccamp2023_rev (マルチバイト)をハッシュ値のキーとして設定しハッシュ値を取得
* 3. 0123456789abcdef (マルチバイト)を初期ベクトルとしてキーを生成
* 4. 得たハッシュ値を使って flagファイルから読み取ったデータを暗号化
* 5. flag.encに書き込み
*
*/


#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

constexpr LPCWSTR HASH_BASE = L"seccamp2023_rev";	// 0xBB60付近に書いてあった  
constexpr LPCWSTR IV = L"0123456789abcdef";			// 初期ベクトル 0xBC00付近に書いてあった

// lea     rax, aSeccamp2023Rev ; "seccamp2023_rev"
// mov     [rsp + 0E8h + lpString], rax
// mov     [rsp + 0E8h + var_50], 0
// mov     rcx, [rsp + 0E8h + lpString]; lpString
// call    cs : lstrlenW
// cdqe
// mov     [rsp + 0E8h + var_48], rax
// mov     rax, [rsp + 0E8h + var_48]
// shl     rax, 1
// mov     qword ptr[rsp + 0E8h + dwDataLen], rax
// 上記命令で2倍してる
const auto HASH_BASE_LENGTH = lstrlenW(HASH_BASE) * 2;

void decrypt(const HANDLE& fileHandle);
bool createHash(const HCRYPTPROV& prov, HCRYPTHASH* const hash);
bool createKey(const HCRYPTPROV& prov, HCRYPTKEY* const key, const HCRYPTHASH& hash);
void releaseObject(const HCRYPTPROV& prov, const HCRYPTHASH& hash, const HCRYPTKEY& key);

int main(void) {
	HANDLE fileHandle = CreateFile(L"flag.enc", GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(fileHandle == INVALID_HANDLE_VALUE) {
		return -1;
	}

	decrypt(fileHandle);

	CloseHandle(fileHandle);

	return 0;
}

void decrypt(const HANDLE& fileHandle) {
	// キーコンテナの取得
	HCRYPTPROV prov = 0;

	// mov     [rsp + 0E8h + var_A8], 0
	// mov     [rsp + 0E8h + var_88], 0
	// mov     [rsp + 0E8h + dwCreationDisposition], 0F0000000h; dwFlags
	// mov     r9d, 18h; dwProvType
	// lea     r8, szProvider; "Microsoft Enhanced RSA and AES Cryptogr"...
	// xor     edx, edx; szContainer
	// lea     rcx, [rsp + 0E8h + phProv]; phProv

	// phProv: prov のアドレス
	// szContainer: xor edx, edx で打ち消してるから0っぽい?
	// szProvider: MS_ENH_RSA_AES_PROV を指定 rdata(0xBB90付近)でも Microsoft Enhanced RSA and AES Cryptographic Provider という文字列が見えたので
	// dwProvType: mov r9d, 18h  となっていたので0x18(リファレンス見ると PROV_RSA_AES )を指定
	// dwFlags: 0 を指定
	if(!CryptAcquireContextW(&prov, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
		return;
	}

	// hash値の生成
	HCRYPTHASH hash;
	if(!createHash(prov, &hash)) {
		releaseObject(prov, NULL, NULL);
		return;
	}

	// キーの生成
	HCRYPTKEY key;
	if(!createKey(prov, &key, hash)) {
		releaseObject(prov, hash, NULL);
		return;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);
	BYTE* buffer = new BYTE[fileSize + 1];
	DWORD numberOfBytesRead = 0;

	// flag.encの読み込み
	const BOOL isRead = ReadFile(fileHandle, buffer, fileSize, &numberOfBytesRead, 0);
	if(!isRead) {
		delete[] buffer;
		releaseObject(prov, hash, key);
		return;
	}

	// mov     dword ptr [rsp+0E8h+hTemplateFile], 280h
	// lea     rax, [rsp + 0E8h + NumberOfBytesRead]
	// mov     qword ptr[rsp + 0E8h + dwFlagsAndAttributes], rax; pdwDataLen
	// mov     rax, [rsp + 0E8h + lpBuffer]
	// mov     qword ptr[rsp + 0E8h + dwCreationDisposition], rax; pbData
	// xor     r9d, r9d; dwFlags
	// mov     r8d, [rsp + 0E8h + Final]; Final
	// xor     edx, edx; hHash
	// mov     rcx, [rsp + 0E8h + phKey]; hKey

	// hkey: mov rcx, [rsp+0E8h+phKey]
	// hHash: xor edx, edx で打ち消してるから0っぽい?
	// Final: 直前の条件( cmp [rsp+0E8h+ver_A0],eax )によって変わるっぽい 
	// dwFlags: xor r9d, r9d で打ち消してるから0っぽい?
	// pbData: lpBuffer を指定 mov qword ptr [rsp+0E8h+dwCreationDisposition], rax -> rax = lpBuffer 直前の命令が mov rax, [rsp+0E8h+lpBuffer]
	// pdwDataLen: NumberOfBytesRead を指定 mov qword ptr [rsp+0E8h+dwFlagsAndAttributes], rax -> rax =  直前の命令が byteRead_NumberOfBytesRead lea rax, [rsp+0E8h+NumberOfBytesRead]
	// dwBufLen: fileSize を指定
	// 
	// CryptEncryptが以上のような引数の受け取りをしたので同じように反映
	const BOOL resultCryptDecrypt = CryptDecrypt(key, 0, TRUE, 0, buffer, &fileSize);
	if(resultCryptDecrypt) {
		buffer[fileSize] = '\0';
		printf_s("decrypt data:%s\n", buffer);
	} else {
		printf_s("decrypt error!\n");
	}

	delete[] buffer;

	releaseObject(prov, hash, key);
}

bool createHash(const HCRYPTPROV& prov, HCRYPTHASH* const hash) {
	// lea     rax, [rsp+0E8h+phHash]
	// mov     qword ptr[rsp + 0E8h + dwCreationDisposition], rax; phHash
	// xor     r9d, r9d; dwFlags
	// xor     r8d, r8d; hKey
	// mov     edx, 800Ch; Algid
	// mov     rcx, [rsp + 0E8h + phProv]; hProv
	// call    cs:CryptCreateHash

	// hProv: prov を指定 直前のphProvを指示していたので
	// Algid: mov edx, 0x800C; Algid となっていたので 0x800C(リファレンス見ると CALG_SHA_256 )を指定
	// hKey: xor r8d, r8d で打ち消してるから0っぽい?
	// dwFlags: xor r9d, r9d で打ち消してるから0っぽい?
	// phHash: 直前に生成(宣言)したhashのアドレス
	if(!CryptCreateHash(prov, CALG_SHA_256, 0, 0, hash)) {
		printf_s("CryptCreateHash error\n");
		return false;
	}

	// xor     r9d, r9d
	// mov     r8d, [rsp + 0E8h + dwDataLen]; dwDataLen
	// mov     rdx, [rsp + 0E8h + lpString]; pbData
	// mov     rcx, [rsp + 0E8h + phHash]; hHash
	// call    cs : CryptHashData

	// hHash: hash を指定 movでphHashを指していたので 
	// pbData: lpString を指定 movで lpString を指していたので
	// dwDetalen: dwDetaLen を指定 movで dwDetaLen を指していたので
	// dwFlags: xor r9d, r9d で打ち消してるから0っぽい?
	if(!CryptHashData(*hash, (BYTE*)HASH_BASE, HASH_BASE_LENGTH, 0)) {
		printf_s("CryptHashData error\n");
		return false;
	}

	return true;
}

bool createKey(const HCRYPTPROV& prov, HCRYPTKEY* const key, const HCRYPTHASH& hash) {
	// lea     rax, [rsp+0E8h+phKey]
	// mov     qword ptr[rsp + 0E8h + dwCreationDisposition], rax; phKey
	// xor     r9d, r9d; dwFlags
	// mov     r8, [rsp + 0E8h + phHash]; hBaseData
	// mov     edx, 6610h; Algid
	// mov     rcx, [rsp + 0E8h + phProv]; hProv
	// call    cs : CryptDeriveKey

	// hProv: prov を指定
	// Algid: mov edx, 0x6610; Alfid となっていたので0x6610(リファレンス見ると CALG_AES_256 )を指定
	// hBaseData: CryptCreateHash直前の hash を指定
	// dwFlags: xor r9d, r9d で打ち消してるから0っぽい?
	// phKey: 直前に生成(宣言)したkeyのアドレス
	if(!CryptDeriveKey(prov, CALG_AES_256, hash, 0, key)) {
		printf_s("CryptDeriveKey error\n");
		return false;
	}

	// lea     rax, a0123456789abcd; "0123456789abcdef"
	// mov     [rsp + 0E8h + pbData], rax
	// xor     r9d, r9d; dwFlags
	// mov     r8, [rsp + 0E8h + pbData]; pbData
	// mov     edx, 1; dwParam
	// mov     rcx, [rsp + 0E8h + phKey]; hKey
	// call    cs : CryptSetKeyParam

	// hkey: 生成したkey
	// dwParam: mov edx, 1 だけどexampleとか見てるとKP_IVのことっぽい?
	// pbData: 初期ベクトル
	// dwFlags: xor r9d, r9d で打ち消してるから0っぽい?
	if(!CryptSetKeyParam(*key, KP_IV, (BYTE*)IV, 0)) {
		printf_s("CryptSetKeyParam error\n");
		return false;
	}

	return true;
}

void releaseObject(const HCRYPTPROV& prov, const HCRYPTHASH& hash, const HCRYPTKEY& key) {
	if(key != NULL) {
		if(!CryptDestroyKey(key)) {
			printf_s("CryptDestroyKey error\n");
		}
	}
	if(hash != NULL) {
		if(!CryptDestroyHash(hash)) {
			printf_s("CryptDestroyHash error\n");
		}
	}
	if(prov != NULL) {
		if(!CryptReleaseContext(prov, 0)) {
			printf_s("CryptReleaseContext error\n");
		}
	}
}
