from pathlib import Path

from digital_key.cli import default_decrypt_output, default_encrypt_output


def test_default_encrypt_output_adds_tdkey_suffix():
    assert default_encrypt_output(Path("report.pdf")) == Path("report.pdf.tdkey")


def test_default_decrypt_output_removes_tdkey_suffix():
    assert default_decrypt_output(Path("report.pdf.tdkey")) == Path("report.pdf")


def test_default_decrypt_output_avoids_source_name_without_suffix():
    assert default_decrypt_output(Path("archive.bin")) == Path("archive.bin.decrypted")
