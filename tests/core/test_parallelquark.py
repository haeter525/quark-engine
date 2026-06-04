# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from quark.core.parallelquark import ParallelQuark


def test_parallel_quark_forwards_dynamic_resolve():
    with patch("quark.core.parallelquark.Pool") as mock_pool, \
         patch("quark.core.parallelquark.Quark.__init__", return_value=None):
        ParallelQuark("fake.apk", "androguard", num_of_process=2, dynamic_resolve=True)
        initargs = mock_pool.call_args[0][2]
        assert initargs[-1] is True


def test_parallel_quark_dynamic_resolve_defaults_false():
    with patch("quark.core.parallelquark.Pool") as mock_pool, \
         patch("quark.core.parallelquark.Quark.__init__", return_value=None):
        ParallelQuark("fake.apk", "androguard", num_of_process=2)
        initargs = mock_pool.call_args[0][2]
        assert initargs[-1] is False
