import pytest

from agent_shield.config import DEFAULT_POLICY
from agent_shield.models import ToolVerdict
from agent_shield.tool_policy import PolicyError, ToolPolicy


@pytest.fixture(scope="module")
def policy() -> ToolPolicy:
    return ToolPolicy.from_file(DEFAULT_POLICY)


def verdict(policy: ToolPolicy, tool: str, **args) -> ToolVerdict:
    return policy.evaluate(tool, args).verdict


def test_unknown_tool_is_denied_by_default(policy):
    decision = policy.evaluate("format_disk", {})
    assert decision.verdict is ToolVerdict.DENY
    assert "not in the allowlist" in decision.reasons[0]


def test_explicitly_disabled_tool_is_denied(policy):
    assert verdict(policy, "run_command", cmd="ls") is ToolVerdict.DENY


class TestFiles:
    def test_path_inside_workspace_is_allowed(self, policy):
        assert verdict(policy, "read_file", path="/workspace/notes/a.txt") is ToolVerdict.ALLOW

    @pytest.mark.parametrize(
        "path",
        [
            "/workspace/../etc/passwd",
            "/workspace/%2e%2e/etc/passwd",
            "/workspace/%252e%252e/etc/passwd",
            "/workspace\\..\\windows\\system32",
            "/etc/passwd",
            "/workspace-evil/secrets",
            "relative/path",
        ],
    )
    def test_traversal_and_escape_attempts_are_denied(self, policy, path):
        assert verdict(policy, "read_file", path=path) is ToolVerdict.DENY

    def test_null_byte_is_denied(self, policy):
        assert verdict(policy, "read_file", path="/workspace/a\x00.txt") is ToolVerdict.DENY


class TestHttp:
    def test_allowed_host_over_https(self, policy):
        assert verdict(policy, "http_get", url="https://api.github.com/repos/x/y") is ToolVerdict.ALLOW

    def test_wildcard_host(self, policy):
        assert verdict(policy, "http_get", url="https://en.wikipedia.org/wiki/X") is ToolVerdict.ALLOW

    @pytest.mark.parametrize(
        "url",
        [
            "http://api.github.com/x",  # not https
            "https://evil.example.org/x",  # host not allowed
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/admin",
            "https://localhost/admin",
            "https://[::1]/admin",
            "https://[::ffff:127.0.0.1]/admin",
            "https://10.0.0.5/",
            "https://2130706433/",  # decimal encoding of 127.0.0.1
            "https://0x7f000001/",  # hex encoding of 127.0.0.1
            "https://db.internal/",
            "https://user:pass@api.github.com/",
            "file:///etc/passwd",
            "https:///nohost",
        ],
    )
    def test_ssrf_and_disallowed_targets_are_denied(self, policy, url):
        assert verdict(policy, "http_get", url=url) is ToolVerdict.DENY

    def test_malformed_url_is_denied(self, policy):
        assert verdict(policy, "http_get", url="https://[bad") is ToolVerdict.DENY


class TestSql:
    def test_select_is_allowed(self, policy):
        assert verdict(policy, "run_sql", query="SELECT id FROM users WHERE id = 1;") is ToolVerdict.ALLOW

    @pytest.mark.parametrize(
        "query",
        [
            "DROP TABLE users",
            "SELECT 1; DROP TABLE users",
            "SELECT * FROM users -- comment",
            "SELECT /* x */ 1",
            "UPDATE users SET admin = 1",
            "select 1; delete from users",
        ],
    )
    def test_destructive_or_stacked_queries_are_denied(self, policy, query):
        assert verdict(policy, "run_sql", query=query) is ToolVerdict.DENY


class TestPayments:
    ok = {"to_account": "GB29NWBK60161331926819", "currency": "USD"}

    def test_small_payment_is_auto_approved(self, policy):
        assert verdict(policy, "send_payment", amount=25, **self.ok) is ToolVerdict.ALLOW

    def test_payment_above_limit_needs_human_approval(self, policy):
        decision = policy.evaluate("send_payment", {"amount": 500, **self.ok})
        assert decision.verdict is ToolVerdict.NEEDS_APPROVAL

    @pytest.mark.parametrize("amount", [5000, 0, -5, True, "10"])
    def test_invalid_or_excessive_amounts_are_denied(self, policy, amount):
        assert verdict(policy, "send_payment", amount=amount, **self.ok) is ToolVerdict.DENY

    def test_unsupported_currency_is_denied(self, policy):
        assert verdict(policy, "send_payment", amount=5, to_account="GB29NWBK60161331926819",
                       currency="BTC") is ToolVerdict.DENY

    def test_missing_required_argument_is_denied(self, policy):
        decision = policy.evaluate("send_payment", {"amount": 5, "currency": "USD"})
        assert decision.verdict is ToolVerdict.DENY
        assert "missing required argument 'to_account'" in decision.reasons

    def test_unexpected_argument_is_denied(self, policy):
        decision = policy.evaluate("send_payment", {"amount": 5, "currency": "USD",
                                                    "to_account": "GB29NWBK60161331926819", "override": True})
        assert decision.verdict is ToolVerdict.DENY
        assert "unexpected argument" in decision.reasons[0]


class TestEmail:
    body = {"subject": "hi", "body": "hello"}

    def test_requires_approval_even_when_valid(self, policy):
        assert verdict(policy, "send_email", to="bob@example.com", **self.body) is ToolVerdict.NEEDS_APPROVAL

    def test_external_recipient_is_denied(self, policy):
        assert verdict(policy, "send_email", to="attacker@evil.test", **self.body) is ToolVerdict.DENY


class TestCustomPolicies:
    def test_default_allow_policy(self):
        permissive = ToolPolicy({"default": "allow"})
        assert permissive.evaluate("anything", {}).verdict is ToolVerdict.ALLOW

    def test_shell_metacharacters_and_patterns(self):
        custom = ToolPolicy({"tools": {"ping": {"args": {"host": {
            "type": "string", "deny_shell_metacharacters": True, "max_length": 20}}}}})
        assert custom.evaluate("ping", {"host": "example.com"}).verdict is ToolVerdict.ALLOW
        assert custom.evaluate("ping", {"host": "a.com; rm -rf /"}).verdict is ToolVerdict.DENY
        assert custom.evaluate("ping", {"host": "$(whoami)"}).verdict is ToolVerdict.DENY
        assert custom.evaluate("ping", {"host": "a" * 50}).verdict is ToolVerdict.DENY

    def test_type_enforcement(self):
        custom = ToolPolicy({"tools": {"t": {"args": {"n": {"type": "integer"}, "s": {"type": "string"},
                                                       "b": {"type": "boolean"}, "x": {"type": "weird"}}}}})
        assert custom.evaluate("t", {"n": 3, "s": "a", "b": True}).verdict is ToolVerdict.ALLOW
        assert custom.evaluate("t", {"n": "3"}).verdict is ToolVerdict.DENY
        assert custom.evaluate("t", {"n": True}).verdict is ToolVerdict.DENY
        assert custom.evaluate("t", {"x": 1}).verdict is ToolVerdict.DENY

    def test_non_strict_tools_accept_extra_arguments(self):
        custom = ToolPolicy({"tools": {"t": {"strict": False, "args": {"a": {"type": "string"}}}}})
        assert custom.evaluate("t", {"a": "x", "extra": 1}).verdict is ToolVerdict.ALLOW

    def test_tool_without_arg_rules_accepts_any_arguments(self):
        assert ToolPolicy({"tools": {"t": {}}}).evaluate("t", {"a": 1}).verdict is ToolVerdict.ALLOW

    @pytest.mark.parametrize(
        "config",
        [{"default": "maybe"}, {"tools": ["not", "a", "dict"]}],
    )
    def test_malformed_policy_is_rejected(self, config):
        with pytest.raises(PolicyError):
            ToolPolicy(config)

    def test_malformed_policy_file_is_rejected(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("- just\n- a list\n")
        with pytest.raises(PolicyError):
            ToolPolicy.from_file(path)

    def test_empty_policy_file_denies_everything(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("")
        assert ToolPolicy.from_file(path).evaluate("x", {}).verdict is ToolVerdict.DENY
