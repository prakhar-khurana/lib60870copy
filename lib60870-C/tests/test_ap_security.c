#include "unity.h"
#include "aprofile_internal.h"
#include "mbedtls/md.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

void test_chunk_header_parsing(void) {
    uint8_t header[12] = {
        0xA1, 
        0x02, 0x00, // total_chunks = 2
        0x00, 0x00, // chunk_index = 0
        0x04, 0x00, // total_length = 4
        0x03, 0x00, // suite_id = 3 (hybrid)
        0x01, 0x02, // kem_id = 0x0201 (ML-KEM-768)
        0x01        // hash_id = 1 (SHA-256)
    };
    
    struct sAProfileContext ctx = {0};
    bool result = ap_chunk_store(&ctx, header[0], header, sizeof(header));
    
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_EQUAL(2, ctx.chunk_expected_total);
    TEST_ASSERT_EQUAL(3, ctx.suite_id);
    TEST_ASSERT_EQUAL(0x0201, ctx.kem_id);
    TEST_ASSERT_EQUAL(1, ctx.hash_id);
}

void test_transcript_hashing(void) {
    struct sAProfileContext ctx = {0};
    mbedtls_md_init(&ctx.th_ctx);
    mbedtls_md_setup(&ctx.th_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx.th_ctx);
    
    uint8_t data[] = {0x01, 0x02, 0x03};
    mbedtls_md_update(&ctx.th_ctx, data, sizeof(data));
    
    uint8_t hash[32];
    mbedtls_md_finish(&ctx.th_ctx, hash);
    
    // Verify known SHA-256 hash of {0x01, 0x02, 0x03}
    uint8_t expected[] = {0x03, 0xac, 0x67, 0x42, 0x16, 0xf3, 0xe1, 0x5c,
                          0x66, 0x28, 0x03, 0x4b, 0x33, 0x36, 0x86, 0xb2,
                          0x84, 0x9a, 0xec, 0x7f, 0x3e, 0x04, 0x14, 0x68,
                          0x0f, 0x3f, 0x24, 0x53, 0x0c, 0x9e, 0x3b, 0xb7};
    
    TEST_ASSERT_EQUAL_MEMORY(expected, hash, sizeof(hash));
}

void test_hkdf_derivation(void) {
    uint8_t ikm[] = "input key material";
    uint8_t salt[] = "salt";
    uint8_t info[] = "context";
    uint8_t okm[32];
    
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                          salt, strlen((char*)salt),
                          ikm, strlen((char*)ikm),
                          info, strlen((char*)info),
                          okm, sizeof(okm));
    
    TEST_ASSERT_EQUAL(0, ret);
    // Add known good HKDF output verification here
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_chunk_header_parsing);
    RUN_TEST(test_transcript_hashing);
    RUN_TEST(test_hkdf_derivation);
    return UNITY_END();
}
