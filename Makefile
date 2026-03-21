#
# Windows-only Makefile for CS4390 P2P project skeleton (MinGW)
# Builds peer and tracker with Winsock2 support.
#

CC      = gcc
CFLAGS  = -Wall -Wextra -g
LDFLAGS = -lws2_32

PEER_SRC    = skeleton_peer.c
TRACKER_SRC = skeleton_tracker.c

PEER_OBJ    = $(PEER_SRC:.c=.o)
TRACKER_OBJ = $(TRACKER_SRC:.c=.o)

PEER_DIRS   = peer1 peer2 peer3
PEER_BINS   = $(PEER_DIRS:%=%/peer)
TRACKER_BIN = tracker
CLEAN_FILES = $(PEER_BINS:%=%.exe) $(TRACKER_BIN:%=%.exe) $(TRACKER_OBJ) $(PEER_OBJ)

.PHONY: all clean

all: $(PEER_BINS) $(TRACKER_BIN)

$(PEER_BINS): %/peer: $(PEER_OBJ) %
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TRACKER_BIN): $(TRACKER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PEER_DIRS):
	mkdir $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-cmd /C del /Q /F $(subst /,\,$(CLEAN_FILES))

