import os
import sys

# r1_post_comment_stub.py
# STAND-IN for R1's "post the PR comment" step. It does NOT talk to GitHub: it records the command R1's workflow
# would run, so the hand-off (a markdown file) is exercised end to end.
# RESOLVED(R1): Implemented in stage `40-pr-comment` of .github/workflows/baseline-pipeline.yml.
#              This stub is retained for offline integration testing without GitHub API access.
#   python3 eval/stubs/r1_post_comment_stub.py <pr_comment.md> <out_dir> [pr_number]


def main():
    comment, out_dir = sys.argv[1], sys.argv[2]
    pr = sys.argv[3] if len(sys.argv) > 3 else "<PR_NUMBER>"
    body = open(comment, encoding="utf-8").read()
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "posted_comment_stub.txt"), "w", encoding="utf-8") as f:
        f.write(f"WOULD RUN: gh pr comment {pr} --body-file {os.path.basename(comment)}\n({len(body)} bytes)\n")
    print(f"[R1 stub] would post {len(body)} bytes to PR {pr}")


if __name__ == "__main__":
    main()
