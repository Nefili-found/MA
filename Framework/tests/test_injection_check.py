# -*- coding: utf-8 -*-
"""injection_check 冒烟测试：源码特征核验路径，不依赖 shell/DB/浏览器。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.injection_check import injection_check, CONF_INJECTION_EVIDENCE

# 1) 语法：动态导入无报错
print("[1] import OK")

# 2) 命令注入：system(变量) 直达、无守卫 → accept 0.88
CMD_VULN = """
void run_cmd(char *cmd) {
    system(cmd);
}
"""
h = {"finding_id": "f-001", "cwe": "CWE-78",
     "location": {"function": "run_cmd"}, "taint_source": "cmd"}
r = injection_check(h, {"code": CMD_VULN})
print("[2] command injection:", r["verdict"], "| conf:", r["confidence"], "|", r["reason"])
assert r["verdict"] == "accept" and r["confidence"] == CONF_INJECTION_EVIDENCE
assert r["evidence"]["direct_input"] is True

# 3) 命令注入：参数数组 execve（安全写法）→ 降级 uncertain，不 reject
CMD_SAFE = """
void run_cmd(char *argv[]) {
    execve("/bin/ls", argv, NULL);
}
"""
h2 = {"finding_id": "f-002", "cwe": "78", "location": {"function": "run_cmd"}}
r2 = injection_check(h2, {"code": CMD_SAFE})
print("[3] command guarded:", r2["verdict"], "|", r2["reason"])
assert r2["verdict"] == "uncertain"

# 4) SQL 注入：prepare + bind 参数化 → uncertain（守卫命中）
SQL_SAFE = """
void load_user(sqlite3 *db, int id) {
    sqlite3_stmt *stmt;
    sqlite3_prepare(db, "select * from users where id=?", -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, id);
}
"""
h3 = {"finding_id": "f-003", "cwe": "89", "location": {"function": "load_user"}}
r3 = injection_check(h3, {"code": SQL_SAFE})
print("[4] SQL guarded:", r3["verdict"], "|", r3["reason"])
assert r3["verdict"] == "uncertain"

# 5) SQL 注入：sprintf 拼字符串直达 sqlite3_exec → accept
SQL_VULN = """
void query_user(sqlite3 *db, char *name) {
    char sql[256];
    sprintf(sql, "select * from users where name='%s'", name);
    sqlite3_exec(db, sql, NULL, NULL, NULL);
}
"""
h4 = {"finding_id": "f-004", "cwe": "CWE-89",
      "location": {"function": "query_user"}, "taint_source": "name"}
r4 = injection_check(h4, {"code": SQL_VULN})
print("[5] SQL injection:", r4["verdict"], "| conf:", r4["confidence"], "|", r4["reason"])
assert r4["verdict"] == "accept" and r4["evidence"]["direct_input"] is True

# 6) XSS：escape 包裹输出 → uncertain（守卫命中）
XSS_SAFE = """
void render(char *name) {
    printf("<div>%s</div>", escape_html(name));
}
"""
h5 = {"finding_id": "f-005", "cwe": "79", "location": {"function": "render"}}
r5 = injection_check(h5, {"code": XSS_SAFE})
print("[6] XSS guarded:", r5["verdict"], "|", r5["reason"])
assert r5["verdict"] == "uncertain"

# 7) XSS：变量直接进 printf、无转义 → accept
XSS_VULN = """
void echo_name(char *name) {
    printf(name);
}
"""
h6 = {"finding_id": "f-006", "cwe": "79", "location": {"function": "echo_name"}}
r6 = injection_check(h6, {"code": XSS_VULN})
print("[7] XSS:", r6["verdict"], "| conf:", r6["confidence"], "|", r6["reason"])
assert r6["verdict"] == "accept"

# 8) 非注入类 CWE → 跳过 uncertain
h7 = {"finding_id": "f-007", "cwe": "119", "location": {"function": "run_cmd"}}
r7 = injection_check(h7, {"code": CMD_VULN})
print("[8] non-injection CWE:", r7["verdict"], "|", r7["reason"])
assert r7["verdict"] == "uncertain" and r7["confidence"] == 0.0

# 9) 空 code / 无 sink → uncertain，永不 reject
r8 = injection_check({"finding_id": "f-008", "cwe": "78"}, {"code": ""})
print("[9] empty code:", r8["verdict"], "|", r8["reason"])
assert r8["verdict"] != "reject"

NO_SINK = "void plain(int x) { return x + 1; }"
r9 = injection_check({"finding_id": "f-009", "cwe": "78",
                      "location": {"function": "plain"}}, {"code": NO_SINK})
print("[10] no sink:", r9["verdict"], "|", r9["reason"])
assert r9["verdict"] == "uncertain"

print("SMOKE OK")
