/*
 * Copyright (c) 2014 Hugh Bailey <obs.jim@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ctype.h>

#include <util/platform.h>
#include <util/bmem.h>
#include <util/dstr.h>
#include "h8819-pipe.h"

struct os_process_pipe
{
	bool read_pipe;
	HANDLE handle_write;
	HANDLE handle_read;
	HANDLE handle_err;
	HANDLE process;
};

static bool create_pipe(HANDLE *input, HANDLE *output)
{
	SECURITY_ATTRIBUTES sa = {0};

	sa.nLength = sizeof(sa);
	sa.bInheritHandle = true;

	if (!CreatePipe(input, output, &sa, 0)) {
		return false;
	}

	return true;
}

static inline bool create_process(const char *cmd_line, HANDLE stdin_handle, HANDLE stdout_handle, HANDLE stderr_handle,
				  HANDLE *process)
{
	PROCESS_INFORMATION pi = {0};
	wchar_t *cmd_line_w = NULL;
	STARTUPINFOW si = {0};
	bool success = false;

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK;
	si.hStdInput = stdin_handle;
	si.hStdOutput = stdout_handle;
	si.hStdError = stderr_handle;

	DWORD flags = 0;
#ifndef SHOW_SUBPROCESSES
	flags = CREATE_NO_WINDOW;
#endif

	os_utf8_to_wcs_ptr(cmd_line, 0, &cmd_line_w);
	if (cmd_line_w) {
		success = !!CreateProcessW(NULL, cmd_line_w, NULL, NULL, true, flags, NULL, NULL, &si, &pi);

		if (success) {
			*process = pi.hProcess;
			CloseHandle(pi.hThread);
		}

		bfree(cmd_line_w);
	}

	return success;
}

#define PIPE_W 0
#define PIPE_R 1
#define PIPE_E 2

os_process_pipe_t *os_process_pipe_create(const char *cmd_line, const char *type)
{
	os_process_pipe_t *pp = NULL;
	bool has[3] = {0, 0, 1};
	HANDLE process;
	HANDLE handle[3][2];
	bool success;

	if (!cmd_line || !type) {
		return NULL;
	}

	for (const char *t = type; *t; t++) {
		switch (*t) {
		case 'w':
			has[PIPE_W] = true;
			break;
		case 'r':
			has[PIPE_R] = true;
			break;
		case 'e':
			has[PIPE_E] = true;
			break;
		default:
			blog(LOG_ERROR, "os_process_pipe_create: bad type: %s", type);
			return NULL;
		}
	}

	for (int i = 0; i < 3; i++) {
		handle[i][0] = NULL;
		handle[i][1] = NULL;
	}

	for (int i = 0; i < 3; i++) {
		if (has[i]) {
			if (!create_pipe(&handle[i][0], &handle[i][1])) {
				goto error;
			}
		}
	}
	if (has[PIPE_W]) {
		success = !!SetHandleInformation(handle[PIPE_W][1], HANDLE_FLAG_INHERIT, false);
		if (!success) {
			goto error;
		}
	}

	if (has[PIPE_R]) {
		success = !!SetHandleInformation(handle[PIPE_R][0], HANDLE_FLAG_INHERIT, false);
		if (!success) {
			goto error;
		}
	}

	success = !!SetHandleInformation(handle[PIPE_E][0], HANDLE_FLAG_INHERIT, false);
	if (!success) {
		goto error;
	}

	success = create_process(cmd_line, handle[PIPE_W][0], handle[PIPE_R][1], handle[PIPE_E][1], &process);
	if (!success) {
		goto error;
	}

	pp = bmalloc(sizeof(*pp));

	pp->handle_write = handle[PIPE_W][1];
	pp->handle_read = handle[PIPE_R][0];
	pp->handle_err = handle[PIPE_E][0];
	pp->process = process;

	if (has[PIPE_W])
		CloseHandle(handle[PIPE_W][0]);
	if (has[PIPE_R])
		CloseHandle(handle[PIPE_R][1]);
	if (has[PIPE_E])
		CloseHandle(handle[PIPE_E][1]);

	return pp;

error:
	for (int i = 0; i < 3; i++) {
		if (handle[i][0])
			CloseHandle(handle[i][0]);
		if (handle[i][1])
			CloseHandle(handle[i][1]);
	}
	return NULL;
}

static bool has_special(const char *s)
{
	for (; *s; s++) {
		if (!isalnum(*s))
			return true;
	}
	return false;
}

static void build_command_line(struct dstr *cmd, const char *argv0, const char *const *argv)
{
	dstr_init(cmd);
	for (int i = 0; argv[i]; i++) {
		const char *ai = i ? argv[i] : argv0;
		if (cmd->len)
			dstr_cat_ch(cmd, ' ');

		if (has_special(ai)) {
			struct dstr tmp;
			dstr_init_copy(&tmp, ai);
			dstr_replace(&tmp, "\"", "\"\"");
			dstr_insert_ch(&tmp, 0, '\"');
			dstr_cat_ch(&tmp, '\"');
			dstr_cat_dstr(cmd, &tmp);
			dstr_free(&tmp);
		}
		else {
			dstr_cat(cmd, ai);
		}
	}
}

os_process_pipe_t *os_process_pipe_create_v(const char *file, char *const argv[], const char *type)
{
	struct dstr cmd_line;
	build_command_line(&cmd_line, file, argv);

	blog(LOG_INFO, "os_process_pipe_create_v: cmd_line='%s'", cmd_line.array);

	os_process_pipe_t *ret = os_process_pipe_create(cmd_line.array, type);

	dstr_free(&cmd_line);

	return ret;
}

int os_process_pipe_destroy(os_process_pipe_t *pp)
{
	int ret = 0;

	if (pp) {
		DWORD code;

		if (pp->handle_write)
			CloseHandle(pp->handle_write);
		if (pp->handle_read)
			CloseHandle(pp->handle_read);
		CloseHandle(pp->handle_err);

		WaitForSingleObject(pp->process, INFINITE);
		if (GetExitCodeProcess(pp->process, &code))
			ret = (int)code;

		CloseHandle(pp->process);
		bfree(pp);
	}

	return ret;
}

size_t os_process_pipe_read(os_process_pipe_t *pp, uint8_t *data, size_t len)
{
	DWORD bytes_read;
	bool success;

	if (!pp) {
		return 0;
	}
	if (!pp->handle_read) {
		return 0;
	}

	success = !!ReadFile(pp->handle_read, data, (DWORD)len, &bytes_read, NULL);
	if (success && bytes_read) {
		return bytes_read;
	}

	return 0;
}

size_t os_process_pipe_read_err(os_process_pipe_t *pp, uint8_t *data, size_t len)
{
	DWORD bytes_read;
	bool success;

	if (!pp || !pp->handle_err) {
		return 0;
	}

	success = !!ReadFile(pp->handle_err, data, (DWORD)len, &bytes_read, NULL);
	if (success && bytes_read) {
		return bytes_read;
	}
	else
		bytes_read = GetLastError();

	return 0;
}

size_t os_process_pipe_write(os_process_pipe_t *pp, const uint8_t *data, size_t len)
{
	DWORD bytes_written;
	bool success;

	if (!pp) {
		return 0;
	}
	if (!pp->handle_write) {
		return 0;
	}

	success = !!WriteFile(pp->handle_write, data, (DWORD)len, &bytes_written, NULL);
	if (success && bytes_written) {
		return bytes_written;
	}

	return 0;
}

uint32_t h8819_process_pipe_wait_read(os_process_pipe_t *pp, uint32_t pipe_mask, uint32_t timeout_ms)
{
	HANDLE handles[2];
	DWORD nCount = 0;

	if (!pp->handle_read)
		pipe_mask &= ~(1 << PIPE_R);
	if (!pp->handle_err)
		pipe_mask &= ~(1 << PIPE_E);

	if (pipe_mask & (1 << PIPE_R))
		handles[nCount++] = pp->handle_read;
	if (pipe_mask & (1 << PIPE_E))
		handles[nCount++] = pp->handle_err;

	if (!nCount)
		return 0;

	DWORD ret = WaitForMultipleObjects(nCount, handles, FALSE, timeout_ms);

	if (pipe_mask & (1 << PIPE_R)) {
		switch (ret) {
		case WAIT_OBJECT_0:
			return 1 << PIPE_R;
		case WAIT_OBJECT_0 + 1:
			return 1 << PIPE_E;
		default:
			return 0;
		}
	}

	if (pipe_mask & (1 << PIPE_E)) {
		switch (ret) {
		case WAIT_OBJECT_0:
			return 1 << PIPE_E;
		default:
			return 0;
		}
	}

	return ret;
}
