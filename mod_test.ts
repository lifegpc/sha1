import { HmacSHA1, sha1 } from "./mod.ts";
import { assertEquals } from "@std/assert";

Deno.test("test_sha1", () => {
    assertEquals(sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assertEquals(
        sha1("helloworld"),
        "6adfb183a4a2c94a2f92dab5ade762a47889a5a1",
    );
    assertEquals(
        sha1("Unicode字符测试"),
        "85fb1f257f545dc05db4a8f22c74598ca9fab23f",
    );
    assertEquals(
        sha1(
            "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890",
        ),
        "fecfd28bbc9345891a66d7c1b8ff46e60192d284",
    );
    assertEquals(
        HmacSHA1("测试key", "测试123456"),
        "1fcb8268268756779f45e0c5d1b249e685b114ca",
    );
});
