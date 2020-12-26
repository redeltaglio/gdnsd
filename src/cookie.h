/* Copyright © 2018 Brandon L Black <blblack@gmail.com>
 *
 * This file is part of gdnsd.
 *
 * gdnsd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * gdnsd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gdnsd.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GDNSD_COOKIE_H
#define GDNSD_COOKIE_H

#include <gdnsd/compiler.h>

#include <gdnsd/net.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include <ev.h>

// cookie_config() must be called first before others!
// If "key_file" is NULL, a random secret will be generated.
void cookie_config(const char* key_file);

// Sets up the hourly runtime secret rotation in the main thread ev loop.
// Without this everything else still "works", but the server secrets and thus
// the server cookies will last forever and eventually become insecure.
F_NONNULL
void cookie_runtime_init(struct ev_loop* loop);

// Called under RCU readlock conditions from iothreads.
// Caller ensures cookie_data_in has minimum 8 bytes (client cookie).  This
// function always populates cookie_data_out with a full 16 bytes of both
// cookies (client copied from input, server generated by this function), and
// the caller must ensure buffer space available for that.
// Retval is boolean validation status
//   true: Client provided a valid server cookie we believe we generated
//   false: Client provided invalid or empty server cookie data
F_NONNULL
bool cookie_process(uint8_t* cookie_data_out, const uint8_t* cookie_data_in, const gdnsd_anysin_t* client, const unsigned cookie_data_in_len);

#endif // GDNSD_COOKIE_H
