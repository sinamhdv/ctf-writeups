#!/bin/bash
socat TCP-LISTEN:12345,reuseaddr,fork EXEC:./allokay,pty,cfmakeraw
