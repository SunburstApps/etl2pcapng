/*

Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

ndis_pcap

Wrapper for netsh.exe and etl2pcap.exe that generates a packet trace when
run interactively, and outputs it as a pcapng file for analysis in Wireshark.

*/

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <process.h>
#include <PathCch.h>

__declspec(noreturn)
static void print_usage(void) {
	fwprintf(stderr, L"ndis_pcap [/noclean] <file.pcap>\n");
	fwprintf(stderr, L"\tCaptures a packet trace file using the built-in Windows NDIS Capture filter\n\n");
	fwprintf(stderr, L"\t/noclean - Do not delete intermediate *.etl file\n");
	exit(-1);
}

int wmain(int argc, const wchar_t** argv) {
	bool clean = true;
	const wchar_t* pcap_filename = NULL;

	argc--; argv++; // skip argv[0]

	while (argc != 0) {
		if (!wcscmp(argv[0], L"-v") || !wcscmp(argv[0], L"--version")) {
			wprintf(L"ndis_pcap version 1.0.0\n");
			return 0;
		}

		if (!wcscmp(argv[0], L"-h") || !wcscmp(argv[0], L"--help") || !wcscmp(argv[0], L"/?")) {
			print_usage();
		}

		if (argv[0][0] == L'/') {
			if (!wcscmp(argv[1], L"/noclean")) {
				clean = false;
			}
			else {
				print_usage();
			}
		}
		else {
			pcap_filename = argv[0];
			break;
		}

		argc--; argv++;
	}

	if (pcap_filename == NULL) {
		print_usage();
	}

	wchar_t* etl_filename = _wcsdup(pcap_filename);
	HRESULT hr = PathCchRenameExtension(etl_filename, wcslen(etl_filename), L".etl");
	if (FAILED(hr)) {
		fwprintf(stderr, L"error: Could not construct file path to intermediate .ETL file\n");
		exit(1);
	}

	wchar_t etl2pcapng_path[MAX_PATH];
	RtlZeroMemory(etl2pcapng_path, MAX_PATH * sizeof(wchar_t));
	if (GetModuleFileNameW(NULL, etl2pcapng_path, MAX_PATH) == 0) {
		fwprintf(stderr, L"error: Could not compute file path of ndis_pcap.exe\n");
		exit(1);
	}

	hr = PathCchRemoveFileSpec(etl2pcapng_path, MAX_PATH);
	if (FAILED(hr)) {
		fwprintf(stderr, L"error: Could not construct file path to etl2pcapng.exe\n");
		exit(1);
	}

	hr = PathCchAppend(etl2pcapng_path, MAX_PATH, L"etl2pcapng.exe");
	if (FAILED(hr)) {
		fwprintf(stderr, L"error: Could not construct file path to etl2pcapng.exe\n");
		exit(1);
	}

	wchar_t traceFileArg[MAX_PATH + 10]; // strlen("traceFile=") == 10
	swprintf_s(traceFileArg, ARRAYSIZE(traceFileArg), L"traceFile=%ls", etl_filename);
	int exitCode = (int)_wspawnlp(_P_WAIT, L"C:\\Windows\\System32\\netsh.exe", L"trace",
		L"start", L"capture=yes", L"report=disabled", traceFileArg, L"sessionname=ndis_pcap", NULL);
	if (exitCode != 0) {
		fwprintf(stderr, L"error: netsh trace start failed with code %d\n", exitCode);
		return 1;
	}

	wprintf(L"Network trace started, press Enter to stop...\n");
	(void)getwchar();

	exitCode = (int)_wspawnlp(_P_WAIT, L"C:\\Windows\\System32\\netsh.exe", L"trace", L"stop", L"sessionname=ndis_pcap", NULL);
	if (exitCode != 0) {
		fwprintf(stderr, L"error: netsh trace stop failed with code %d\n", exitCode);
		return 1;
	}

	exitCode = (int)_wspawnlp(_P_WAIT, etl2pcapng_path, etl_filename, pcap_filename, NULL);
	if (exitCode != 0) {
		fwprintf(stderr, L"error: etl2pcapng failed with code %d\n", exitCode);
	}

	if (clean) {
		BOOL success = DeleteFileW(etl_filename);
		if (!success) {
			fwprintf(stderr, L"note: could not delete temporary ETL file as requested\n");
		}
	}

	return exitCode;
}
