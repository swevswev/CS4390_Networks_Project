#
# Windows-only Makefile for CS4390 P2P project skeleton (MinGW)
# Builds peer and tracker with Winsock2 support.
#
# If link fails with "Permission denied", stop running peers:
#   Get-Process peer -ErrorAction SilentlyContinue | Stop-Process -Force
#

CC      = gcc
CFLAGS  = -Wall -Wextra -g
LDFLAGS = -lws2_32

PEER_SRC    = skeleton_peer.c
TRACKER_SRC = skeleton_tracker.c

PEER_OBJ    = $(PEER_SRC:.c=.o)
TRACKER_OBJ = $(TRACKER_SRC:.c=.o)

# Match final_demo layout (peer1..peer13); all use the same binary linked into each folder.
PEER_DIRS   = peer1 peer2 peer3 peer4 peer5 peer6 peer7 peer8 peer9 peer10 peer11 peer12 peer13
# Explicit .exe avoids MinGW oddities with -o peer1/peer (and matches clean / scripts).
PEER_BINS   = $(PEER_DIRS:%=%/peer.exe)
TRACKER_BIN = tracker.exe
CLEAN_FILES = $(PEER_BINS) $(TRACKER_BIN) $(TRACKER_OBJ) $(PEER_OBJ)

.PHONY: all clean

all: $(PEER_BINS) $(TRACKER_BIN)

$(PEER_BINS): %/peer.exe: $(PEER_OBJ) %
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TRACKER_BIN): $(TRACKER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PEER_DIRS):
	cmd /C "if not exist $@ mkdir $@"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-cmd /C del /Q /F $(subst /,\,$(CLEAN_FILES)) 2>nul
