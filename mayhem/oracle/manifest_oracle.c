/*
 * manifest_oracle.c — golden known-answer oracle over the EXACT fuzzed parse path
 * (loader_get_json + the loader's vendored cJSON), for vulkan-loader/mayhem/test.sh.
 *
 * This is the same surface json_load_fuzzer drives: loader_get_json() reads a manifest file
 * and parses it with loader_cJSON_ParseWithLength(). The oracle asserts a real semantic answer
 * over that path so a no-op / "return success" patch to the parser cannot pass:
 *
 *   T1  a well-formed ICD manifest PARSES, and the nested object/string values are READ BACK
 *       byte-exactly (file_format_version, ICD.library_path, ICD.api_version).
 *   T2  a well-formed layer manifest PARSES, and layer.name / layer.type read back exactly.
 *   T3  a syntactically MALFORMED manifest is REJECTED (loader_get_json != VK_SUCCESS and *json
 *       stays NULL) — i.e. the parser actually validates, it doesn't blindly accept.
 *   T4  a numeric / nesting edge manifest PARSES and a deep value reads back exactly.
 *
 * Each check prints "ok N - <name>" / "not ok N - <name>" (TAP-ish); main() returns the failure
 * count so the runner (mayhem/test.sh) can exit non-zero and emit CTRF.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "loader.h"
#include "loader_json.h"

static int g_pass = 0, g_fail = 0;

static void report(int cond, const char *name) {
    if (cond) {
        printf("ok %d - %s\n", ++g_pass + g_fail, name);
    } else {
        printf("not ok %d - %s\n", g_pass + ++g_fail, name);
    }
}

/* Write text to a temp file and parse it via the fuzzed entry point. Returns the VkResult and the
 * parsed tree (caller frees with loader_cJSON_Delete). */
static VkResult parse_manifest(const char *text, cJSON **out_json) {
    char path[] = "/tmp/vl_oracle_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { *out_json = NULL; return VK_ERROR_INITIALIZATION_FAILED; }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) { close(fd); unlink(path); *out_json = NULL; return VK_ERROR_INITIALIZATION_FAILED; }
    fwrite(text, 1, strlen(text), fp);
    fclose(fp);
    VkResult res = loader_get_json(NULL, path, out_json);
    unlink(path);
    return res;
}

static const char *getstr(cJSON *obj, const char *key) {
    cJSON *it = loader_cJSON_GetObjectItem(obj, key);
    return (it && it->valuestring) ? it->valuestring : NULL;
}

int main(void) {
    cJSON *json = NULL;
    const char *s;

    /* ── T1: well-formed ICD manifest ── */
    const char *icd =
        "{\"file_format_version\":\"1.0.0\","
        "\"ICD\":{\"library_path\":\"libvulkan_test.so\",\"api_version\":\"1.2.0\"}}";
    json = NULL;
    {
        int ok = (parse_manifest(icd, &json) == VK_SUCCESS) && json != NULL;
        report(ok, "icd manifest parses");
        if (ok) {
            s = getstr(json, "file_format_version");
            report(s && strcmp(s, "1.0.0") == 0, "icd file_format_version == 1.0.0");
            cJSON *icd_obj = loader_cJSON_GetObjectItem(json, "ICD");
            s = icd_obj ? getstr(icd_obj, "library_path") : NULL;
            report(s && strcmp(s, "libvulkan_test.so") == 0, "icd library_path round-trips");
            s = icd_obj ? getstr(icd_obj, "api_version") : NULL;
            report(s && strcmp(s, "1.2.0") == 0, "icd api_version round-trips");
        } else {
            report(0, "icd file_format_version == 1.0.0");
            report(0, "icd library_path round-trips");
            report(0, "icd api_version round-trips");
        }
        if (json) loader_cJSON_Delete(json);
    }

    /* ── T2: well-formed layer manifest ── */
    const char *layer =
        "{\"file_format_version\":\"1.2.0\","
        "\"layer\":{\"name\":\"VK_LAYER_test\",\"type\":\"GLOBAL\","
        "\"library_path\":\"libVkLayer_test.so\",\"api_version\":\"1.3.231\"}}";
    json = NULL;
    {
        int ok = (parse_manifest(layer, &json) == VK_SUCCESS) && json != NULL;
        report(ok, "layer manifest parses");
        if (ok) {
            cJSON *lobj = loader_cJSON_GetObjectItem(json, "layer");
            s = lobj ? getstr(lobj, "name") : NULL;
            report(s && strcmp(s, "VK_LAYER_test") == 0, "layer name round-trips");
            s = lobj ? getstr(lobj, "type") : NULL;
            report(s && strcmp(s, "GLOBAL") == 0, "layer type round-trips");
        } else {
            report(0, "layer name round-trips");
            report(0, "layer type round-trips");
        }
        if (json) loader_cJSON_Delete(json);
    }

    /* ── T3: malformed manifest must be REJECTED ──
     * loader_get_json() signals "invalid JSON" by leaving *json == NULL (it logs the error but
     * returns VK_SUCCESS unless it hit OOM), so the rejection check is *json == NULL — exactly the
     * branch json_load_fuzzer takes (`if (json == NULL) goto out;`). A parser that blindly accepted
     * garbage would return a non-NULL tree here and fail this check. */
    json = NULL;
    {
        /* unterminated object — not valid JSON */
        parse_manifest("{\"file_format_version\": \"1.0.0\", \"ICD\": {", &json);
        report(json == NULL, "malformed manifest is rejected (incomplete object)");
        if (json) loader_cJSON_Delete(json);
        json = NULL;
        /* not JSON at all */
        parse_manifest("this is definitely not json", &json);
        report(json == NULL, "malformed manifest is rejected (non-json text)");
        if (json) loader_cJSON_Delete(json);
    }

    /* ── T4: nested array / numeric edge ── */
    const char *nested =
        "{\"file_format_version\":\"1.0.1\","
        "\"layer\":{\"name\":\"VK_LAYER_nested\",\"type\":\"INSTANCE\","
        "\"instance_extensions\":[{\"name\":\"VK_EXT_debug_utils\",\"spec_version\":\"1\"}]}}";
    json = NULL;
    {
        int ok = (parse_manifest(nested, &json) == VK_SUCCESS) && json != NULL;
        report(ok, "nested manifest parses");
        if (ok) {
            cJSON *lobj = loader_cJSON_GetObjectItem(json, "layer");
            cJSON *exts = lobj ? loader_cJSON_GetObjectItem(lobj, "instance_extensions") : NULL;
            cJSON *first = exts ? exts->child : NULL;
            s = first ? getstr(first, "name") : NULL;
            report(s && strcmp(s, "VK_EXT_debug_utils") == 0, "nested extension name round-trips");
        } else {
            report(0, "nested extension name round-trips");
        }
        if (json) loader_cJSON_Delete(json);
    }

    printf("# passed %d failed %d\n", g_pass, g_fail);
    return g_fail;
}
