"""Content bindings for the asynchronous Hooks harness."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .generated import ContentReference, ContentUploadReceipt

from ._models.content import OwnedAttachment as OwnedAttachment
from ._content import ContentContext as ContentContext
from ._content import ContentSources as ContentSources
from ._content import OwnedContentSource as OwnedContentSource
from .attachment import (
    Attachment as Attachment,
    AttachmentContents as AttachmentContents,
)


def reference(receipt: ContentUploadReceipt) -> ContentReference:
    """Convert a validated upload receipt to its ref-only wire reference.

    Upload confirmation metadata belongs to the receipt, never event content.
    """
    from .runtime import Validator

    Validator().validate("content-upload-receipt", receipt)
    return {"ref": receipt["ref"]}
