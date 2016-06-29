#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) 2016, Joyent, Inc.
#

connbal: connbal.c hash.c packet.c
	$(CC) -o $@ $^

clean:
	rm -f connbal
