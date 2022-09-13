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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include <util/bmem.h>
#include "h8819-pipe.h"

struct os_process_pipe
{
	int fd_write;
	int fd_read;
	int fd_error;
	pid_t pid;
};

#define PIPE_W 0
#define PIPE_R 1
#define PIPE_E 2

static os_process_pipe_t *os_process_pipe_create_internal(void (*cb)(void *), void *data, const char *type)
{
	bool has[3] = {0};
	int fd[3][2];
	pid_t pid;
	struct os_process_pipe *out;

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
		fd[i][0] = -1;
		fd[i][1] = -1;
	}

	for (int i = 0; i < 3; i++) {
		if (has[i]) {
			if (pipe(fd[i]) < 0) {
				blog(LOG_ERROR, "failed to create pipe");
				goto fail1;
			}
		}
	}

	pid = fork();
	if (pid < 0) {
		blog(LOG_ERROR, "failed to fork");
		goto fail1;
	}

	if (pid == 0) {
		// I'm a child
		for (int i = 0; i < 3; i++) {
			if (has[i]) {
				dup2(fd[i][i ? 1 : 0], i);
				close(fd[i][0]);
				close(fd[i][1]);
				fd[i][0] = -1;
				fd[i][1] = -1;
			}
		}

		cb(data);
		fprintf(stderr, "Error: failed to exec\n");
		close(0);
		close(1);
		close(2);
		exit(1);
	}

	out = bmalloc(sizeof(struct os_process_pipe));
	out->pid = pid;

	if (has[PIPE_W]) {
		out->fd_write = fd[PIPE_W][1];
		close(fd[PIPE_W][0]);
	}
	else {
		out->fd_write = -1;
	}

	if (has[PIPE_R]) {
		out->fd_read = fd[PIPE_R][0];
		close(fd[PIPE_R][1]);
	}
	else {
		out->fd_read = -1;
	}

	if (has[PIPE_E]) {
		out->fd_error = fd[PIPE_E][0];
		close(fd[PIPE_E][1]);
	}
	else {
		out->fd_error = -1;
	}

	return out;

fail1:
	for (int i = 0; i < 3; i++) {
		if (fd[i][0] >= 0)
			close(fd[i][0]);
		if (fd[i][1] >= 0)
			close(fd[i][1]);
	}
	return NULL;
}

struct os_process_pipe_create_v_s
{
	const char *file;
	char *const *argv;
};
static void os_process_pipe_create_v_cb(void *data)
{
	struct os_process_pipe_create_v_s *ctx = data;
	execv(ctx->file, ctx->argv);
}
os_process_pipe_t *os_process_pipe_create_v(const char *file, char *const argv[], const char *type)
{
	struct os_process_pipe_create_v_s ctx = {file, argv};
	return os_process_pipe_create_internal(os_process_pipe_create_v_cb, &ctx, type);
}

int os_process_pipe_destroy(os_process_pipe_t *pp)
{
	int ret = 0;

	if (pp) {
		if (pp->fd_write >= 0)
			close(pp->fd_write);

		int status;
		waitpid(pp->pid, &status, 0);
		if (WIFEXITED(status))
			ret = (int)(char)WEXITSTATUS(status);

		if (pp->fd_read >= 0)
			close(pp->fd_read);
		if (pp->fd_error >= 0)
			close(pp->fd_error);

		bfree(pp);
	}

	return ret;
}

size_t os_process_pipe_read(os_process_pipe_t *pp, uint8_t *data, size_t len)
{
	if (!pp)
		return 0;
	if (pp->fd_read < 0)
		return 0;

	ssize_t ret = read(pp->fd_read, data, len);
	return ret > 0 ? (size_t)ret : 0;
}

size_t os_process_pipe_read_err(os_process_pipe_t *pp, uint8_t *data, size_t len)
{
	if (!pp)
		return 0;
	if (pp->fd_error < 0)
		return 0;

	ssize_t ret = read(pp->fd_error, data, len);
	return ret > 0 ? (size_t)ret : 0;
}

size_t os_process_pipe_write(os_process_pipe_t *pp, const uint8_t *data, size_t len)
{
	if (!pp)
		return 0;
	if (pp->fd_write < 0)
		return 0;

	size_t written = 0;
	while (written < len) {
		ssize_t ret = write(pp->fd_write, data + written, len - written);
		if (ret < 0)
			break;
		written += (size_t)ret;
	}
	return written;
}

uint32_t h8819_process_pipe_wait_read(os_process_pipe_t *pp, uint32_t pipe_mask, uint32_t timeout_ms)
{
	int fd_max = 0;
	fd_set readfds;

	if ((pipe_mask & (1 << PIPE_R)) && pp->fd_read < 0)
		pipe_mask &= ~(1 << PIPE_R);
	if ((pipe_mask & (1 << PIPE_E)) && pp->fd_error < 0)
		pipe_mask &= ~(1 << PIPE_E);

	FD_ZERO(&readfds);
	if (pipe_mask & (1 << PIPE_R)) {
		if (pp->fd_read > fd_max)
			fd_max = pp->fd_read;
		FD_SET(pp->fd_read, &readfds);
	}
	if (pipe_mask & (1 << PIPE_E)) {
		if (pp->fd_error > fd_max)
			fd_max = pp->fd_error;
		FD_SET(pp->fd_error, &readfds);
	}

	struct timeval timeout = {.tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000};
	int ret_select = select(fd_max + 1, &readfds, NULL, NULL, &timeout);

	if (ret_select <= 0)
		return 0;

	if ((pipe_mask & (1 << PIPE_R)) && !FD_ISSET(pp->fd_read, &readfds))
		pipe_mask &= ~(1 << PIPE_R);
	if ((pipe_mask & (1 << PIPE_E)) && !FD_ISSET(pp->fd_error, &readfds))
		pipe_mask &= ~(1 << PIPE_E);

	return pipe_mask;
}
