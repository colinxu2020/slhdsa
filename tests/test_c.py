from pathlib import Path

import slhdsa


def test1(tmp_path: Path) -> None:
    sec = slhdsa.KeyPair.gen(slhdsa.sha2_256s).sec
    sec_path = tmp_path / 'sec.pem'
    sec.to_pkcs(sec_path.as_posix())
    assert sec.from_pkcs(sec_path.as_posix()) == sec
