# Copyright 2026 Kazeshini Authors
# SPDX-License-Identifier: Apache-2.0
"""WCAG AA Contrast verification script."""

def rel_lum(hex_c):
    hex_c = hex_c.lstrip("#")
    r, g, b = [int(hex_c[i:i+2], 16) / 255.0 for i in (0, 2, 4)]
    def adj(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * adj(r) + 0.7152 * adj(g) + 0.0722 * adj(b)

def contrast(c1, c2):
    l1, l2 = rel_lum(c1), rel_lum(c2)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)

bg_colors = {"--bg": "#0B0C10", "--panel": "#11131A"}
fg_tokens = {
    "--text": "#D8DEE9",
    "--dim": "#7D8597",
    "--mint": "#8FFFC8",
    "--cyan": "#8FE9FF",
    "--lavender": "#B9A7FF",
    "--peach": "#FFB89A",
    "--rose": "#FF9EC7",
}

print("{:<12} | {:<8} | {:<10} | {:<8} | {:<18}".format("Token", "Hex", "Against", "Ratio", "WCAG AA (>=4.5:1)"))
print("-" * 65)

all_pass = True
for bg_name, bg_val in bg_colors.items():
    for fg_name, fg_val in fg_tokens.items():
        ratio = contrast(fg_val, bg_val)
        status = "PASS" if ratio >= 4.5 else "FAIL"
        if status == "FAIL":
            all_pass = False
        print("{:<12} | {:<8} | {:<10} | {:>6.2f}:1 | {}".format(fg_name, fg_val, bg_name, ratio, status))

print("-" * 65)
print("Overall Result: {}".format("ALL PASSED" if all_pass else "FAILED"))

