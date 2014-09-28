/*
 *
 *	This is free software. You can redistribute it and/or modify under
 *	the terms of the GNU General Public License version 2.
 *
 * 	Copyright (C) 1998 by kra
 *
 */
#include "hunt.h"
#include <termios.h>
#include <unistd.h>
#include <stdio.h>

static struct termios	save_termios;
static int		ttysavefd = -1;
static enum { RESET, RAW, CBREAK }	ttystate = RESET;

/* put terminal into a cbreak mode */
int tty_cbreak(int fd, int wait_for_chars, int timer_dsec)
{
	struct termios	buf;

	if (tcgetattr(fd, &save_termios) < 0)
		return -1;
	buf = save_termios;
	buf.c_lflag &= ~(ECHO | ICANON); /* echo off, canonical mode off */

	buf.c_cc[VMIN] = wait_for_chars;
	buf.c_cc[VTIME] = timer_dsec;

	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return -1;
	ttystate = CBREAK;
	ttysavefd = fd;
	return 0;
}

/* put terminal into a raw mode */
int tty_raw(int fd, int wait_for_chars, int timer_dsec)
{
	struct termios	buf;

	if (tcgetattr(fd, &save_termios) < 0)
		return -1;

	buf = save_termios;

	buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
					/* echo off, canonical mode off, extended input
					   processing off, signal chars off */
	buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
					/* no SIGINT on BREAK, CR-to-NL off, input parity
					   check off, don't strip 8th bit on input,
					   output flow control off */
	buf.c_cflag &= ~(CSIZE | PARENB);
					/* clear size bits, parity checking off */
	buf.c_cflag |= CS8;
					/* set 8 bits/char */

	buf.c_oflag &= ~(OPOST);
					/* output processing off */

	buf.c_cc[VMIN] = wait_for_chars;
	buf.c_cc[VTIME] = timer_dsec;
	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return -1;
	ttystate = RAW;
	ttysavefd = fd;
	return 0;
}

/* restore terminal's mode */
int tty_reset(int fd)
{
	if (ttystate != CBREAK && ttystate != RAW)
		return 0;

	if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0)
		return -1;
	ttystate = RESET;
	return(0);
}

/* can be set up by atexit(tty_atexit) */
void tty_atexit(void)
{
	if (ttysavefd >= 0 && ttystate != RESET)
		tty_reset(ttysavefd);
}

/* reset linux terminal */
void tty_tput_reset(void)
{
	printf("\033c\033]R");
	fflush(stdout);
}

