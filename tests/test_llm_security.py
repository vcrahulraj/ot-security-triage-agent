from __future__ import annotations

import unittest

from ot_triage_agent.llm import LLMConfig, LLMError, parse_allowed_hosts


class LLMEndpointSecurityTests(unittest.TestCase):
    def test_approved_https_endpoint_is_normalized(self) -> None:
        config = LLMConfig(base_url="https://api.openai.com/v1/", model="test")
        self.assertEqual(
            config.chat_completions_url,
            "https://api.openai.com/v1/chat/completions",
        )

    def test_unsafe_or_unapproved_endpoints_are_rejected(self) -> None:
        unsafe_urls = (
            "http://api.openai.com/v1",
            "https://attacker.example/v1",
            "https://user:pass@api.openai.com/v1",
            "https://api.openai.com/v1?redirect=attacker.example",
        )
        for url in unsafe_urls:
            with self.subTest(url=url):
                with self.assertRaises(LLMError):
                    _ = LLMConfig(base_url=url, model="test").chat_completions_url

    def test_operator_can_explicitly_allow_a_compatible_host(self) -> None:
        hosts = parse_allowed_hosts("models.example.org, inference.example.org")
        config = LLMConfig(
            base_url="https://models.example.org/v1",
            model="test",
            allowed_hosts=hosts,
        )
        self.assertEqual(
            config.chat_completions_url,
            "https://models.example.org/v1/chat/completions",
        )


if __name__ == "__main__":
    unittest.main()
