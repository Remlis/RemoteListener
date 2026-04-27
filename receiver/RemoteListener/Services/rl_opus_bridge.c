// rl_opus_bridge.c — C bridge for Opus decoder, to be compiled with libopus
//
// This file wraps the opus_decode API for use from Swift.
// It requires libopus headers to be available at compile time
// and libopus to be linked at runtime (via XCFramework).

#include <stddef.h>
#include <stdint.h>
#include <opus/opus.h>

void *rl_opus_bridge_decoder_create(int32_t *error) {
    OpusDecoder *dec = opus_decoder_create(48000, 1, error);
    return (void *)dec;
}

void rl_opus_bridge_decoder_destroy(void *decoder) {
    if (decoder) {
        opus_decoder_destroy((OpusDecoder *)decoder);
    }
}

int32_t rl_opus_bridge_decode(void *decoder,
                               const uint8_t *data,
                               size_t len,
                               int16_t *pcm,
                               int32_t max_frame_size) {
    if (!decoder || !data || !pcm) return -1;
    return opus_decode((OpusDecoder *)decoder, data, (opus_int32)len,
                       pcm, max_frame_size, 0);
}
