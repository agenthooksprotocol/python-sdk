import unittest
from typing import TypedDict

from agenthooksprotocol.codec import Codec, IdentityCodec
from agenthooksprotocol.generated import JsonValue


class ReadInput(TypedDict):
    path: str


class CodecTests(unittest.TestCase):
    def test_identity_copies_nested_json(self):
        original: JsonValue = {"nested": ["original"]}
        codec: Codec[JsonValue] = IdentityCodec()
        decoded = codec.decode(original)
        decoded["nested"].append("changed")
        self.assertEqual(original, {"nested": ["original"]})
        self.assertEqual(codec.encode(original), original)
        self.assertIsNot(codec.encode(original), original)

    def test_typed_dict_is_not_runtime_validation(self):
        # This is normal Python behavior, not a protocol or application validator.
        self.assertEqual(ReadInput(path=42), {"path": 42})

    def test_optional_pydantic_codec_validates_explicitly(self):
        try:
            from pydantic import BaseModel, TypeAdapter, ValidationError
            from agenthooksprotocol.integrations.pydantic import PydanticCodec
        except ImportError:
            self.skipTest("optional Pydantic integration not installed")

        class ReadArguments(BaseModel):
            path: str

        codec = PydanticCodec(TypeAdapter(ReadArguments))
        self.assertEqual(codec.decode({"path": "notes.txt"}).path, "notes.txt")
        self.assertEqual(
            codec.encode(ReadArguments(path="notes.txt")), {"path": "notes.txt"}
        )
        with self.assertRaises(ValidationError):
            codec.decode({"path": 42})


if __name__ == "__main__":
    unittest.main()
