/*
* @author Sin0n0me
*
* �o�C�i���G�f�B�^�Ŕ`������IDA�ŋt�A�Z���u���������� wincrypt.h �𗘗p�����Í������Ă�?
*
* �ȉ��̂悤�ȗ�����ۂ��̂ŃL�[�𓯂��菇�Őݒ肷���flag.enc�̒��g��CryptDecrypt()�ŕ����ł�����
* 1. flag�t�@�C������Í����O�f�[�^�ǂݎ��
* 2. seccamp2023_rev (�}���`�o�C�g)���n�b�V���l�̃L�[�Ƃ��Đݒ肵�n�b�V���l���擾
* 3. 0123456789abcdef (�}���`�o�C�g)�������x�N�g���Ƃ��ăL�[�𐶐�
* 4. �����n�b�V���l���g���� flag�t�@�C������ǂݎ�����f�[�^���Í���
* 5. flag.enc�ɏ�������
*
*/


#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

constexpr LPCWSTR HASH_BASE = L"seccamp2023_rev";	// 0xBB60�t�߂ɏ����Ă�����  
constexpr LPCWSTR IV = L"0123456789abcdef";			// �����x�N�g�� 0xBC00�t�߂ɏ����Ă�����

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
// ��L���߂�2�{���Ă�
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
	// �L�[�R���e�i�̎擾
	HCRYPTPROV prov = 0;

	// mov     [rsp + 0E8h + var_A8], 0
	// mov     [rsp + 0E8h + var_88], 0
	// mov     [rsp + 0E8h + dwCreationDisposition], 0F0000000h; dwFlags
	// mov     r9d, 18h; dwProvType
	// lea     r8, szProvider; "Microsoft Enhanced RSA and AES Cryptogr"...
	// xor     edx, edx; szContainer
	// lea     rcx, [rsp + 0E8h + phProv]; phProv

	// phProv: prov �̃A�h���X
	// szContainer: xor edx, edx �őł������Ă邩��0���ۂ�?
	// szProvider: MS_ENH_RSA_AES_PROV ���w�� rdata(0xBB90�t��)�ł� Microsoft Enhanced RSA and AES Cryptographic Provider �Ƃ��������񂪌������̂�
	// dwProvType: mov r9d, 18h  �ƂȂ��Ă����̂�0x18(���t�@�����X����� PROV_RSA_AES )���w��
	// dwFlags: 0 ���w��
	if(!CryptAcquireContextW(&prov, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
		return;
	}

	// hash�l�̐���
	HCRYPTHASH hash;
	if(!createHash(prov, &hash)) {
		releaseObject(prov, NULL, NULL);
		return;
	}

	// �L�[�̐���
	HCRYPTKEY key;
	if(!createKey(prov, &key, hash)) {
		releaseObject(prov, hash, NULL);
		return;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);
	BYTE* buffer = new BYTE[fileSize + 1];
	DWORD numberOfBytesRead = 0;

	// flag.enc�̓ǂݍ���
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
	// hHash: xor edx, edx �őł������Ă邩��0���ۂ�?
	// Final: ���O�̏���( cmp [rsp+0E8h+ver_A0],eax )�ɂ���ĕς����ۂ� 
	// dwFlags: xor r9d, r9d �őł������Ă邩��0���ۂ�?
	// pbData: lpBuffer ���w�� mov qword ptr [rsp+0E8h+dwCreationDisposition], rax -> rax = lpBuffer ���O�̖��߂� mov rax, [rsp+0E8h+lpBuffer]
	// pdwDataLen: NumberOfBytesRead ���w�� mov qword ptr [rsp+0E8h+dwFlagsAndAttributes], rax -> rax =  ���O�̖��߂� byteRead_NumberOfBytesRead lea rax, [rsp+0E8h+NumberOfBytesRead]
	// dwBufLen: fileSize ���w��
	// 
	// CryptEncrypt���ȏ�̂悤�Ȉ����̎󂯎��������̂œ����悤�ɔ��f
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

	// hProv: prov ���w�� ���O��phProv���w�����Ă����̂�
	// Algid: mov edx, 0x800C; Algid �ƂȂ��Ă����̂� 0x800C(���t�@�����X����� CALG_SHA_256 )���w��
	// hKey: xor r8d, r8d �őł������Ă邩��0���ۂ�?
	// dwFlags: xor r9d, r9d �őł������Ă邩��0���ۂ�?
	// phHash: ���O�ɐ���(�錾)����hash�̃A�h���X
	if(!CryptCreateHash(prov, CALG_SHA_256, 0, 0, hash)) {
		printf_s("CryptCreateHash error\n");
		return false;
	}

	// xor     r9d, r9d
	// mov     r8d, [rsp + 0E8h + dwDataLen]; dwDataLen
	// mov     rdx, [rsp + 0E8h + lpString]; pbData
	// mov     rcx, [rsp + 0E8h + phHash]; hHash
	// call    cs : CryptHashData

	// hHash: hash ���w�� mov��phHash���w���Ă����̂� 
	// pbData: lpString ���w�� mov�� lpString ���w���Ă����̂�
	// dwDetalen: dwDetaLen ���w�� mov�� dwDetaLen ���w���Ă����̂�
	// dwFlags: xor r9d, r9d �őł������Ă邩��0���ۂ�?
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

	// hProv: prov ���w��
	// Algid: mov edx, 0x6610; Alfid �ƂȂ��Ă����̂�0x6610(���t�@�����X����� CALG_AES_256 )���w��
	// hBaseData: CryptCreateHash���O�� hash ���w��
	// dwFlags: xor r9d, r9d �őł������Ă邩��0���ۂ�?
	// phKey: ���O�ɐ���(�錾)����key�̃A�h���X
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

	// hkey: ��������key
	// dwParam: mov edx, 1 ������example�Ƃ����Ă��KP_IV�̂��Ƃ��ۂ�?
	// pbData: �����x�N�g��
	// dwFlags: xor r9d, r9d �őł������Ă邩��0���ۂ�?
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
