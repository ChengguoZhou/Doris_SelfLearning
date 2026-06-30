"""Correctness tests for the DynDoris functional prototype."""

import unittest

from dyn_doris import DynDorisClient
from dyn_doris.dyn_doris_run_builder import make_search_token


class DynDorisCorrectnessTest(unittest.TestCase):
    def test_setup_search_single_keyword(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a", "b"], "d2": ["b"], "d3": ["c"]})

        self.assertEqual(client.search(["a"]), ["d1"])
        self.assertEqual(client.search(["b"]), ["d1", "d2"])

    def test_add_keyword_tombstones_old_version_and_new_version_matches(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a"]})
        old_vid = client.state.DocState["d1"].vid

        client.update("add", "b", "d1")
        self.assertEqual(len(client.state.BufA), 1)
        self.assertEqual(len(client.state.BufD), 1)
        self.assertEqual(client.state.BufD[0].vid_old, old_vid)
        client.flush_add_buffer()
        client.flush_delete_buffer()

        self.assertEqual(client.search(["a", "b"]), ["d1"])
        debug = client.search_debug(["a"])
        self.assertEqual(debug.ids, ["d1"])
        self.assertGreaterEqual(debug.killed_count, 1)

    def test_delete_keyword_tombstones_old_version_and_keeps_nonempty_new_version(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a", "b"]})
        old_vid = client.state.DocState["d1"].vid

        client.update("delete", "b", "d1")
        self.assertEqual(len(client.state.BufA), 1)
        self.assertEqual(len(client.state.BufD), 1)
        self.assertEqual(client.state.BufD[0].vid_old, old_vid)
        client.flush_add_buffer()
        client.flush_delete_buffer()

        self.assertEqual(client.search(["a"]), ["d1"])
        self.assertEqual(client.search(["a", "b"]), [])

    def test_multikeyword_tombstone_run_is_filtered_by_doris_search(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a", "b"], "d2": ["a"]})
        client.update("delete", "b", "d1")
        client.flush_add_buffer()
        client.flush_delete_buffer()

        debug_matching = client.search_debug(["a", "b"])
        debug_nonmatching = client.search_debug(["a", "c"])

        self.assertEqual(debug_matching.tombstone_count, 1)
        self.assertEqual(debug_nonmatching.tombstone_count, 0)

    def test_client_filter_kills_dead_vid_and_server_does_not(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a"]})
        client.update("add", "b", "d1")
        client.flush_add_buffer()
        client.flush_delete_buffer()

        add_tokens = [
            make_search_token(client.server.add_runs[run_id], ["a"], client.keys)
            for run_id in client.state.RunTbl
        ]
        delete_tokens = [
            make_search_token(client.server.delete_runs[run_id], ["a"], client.keys)
            for run_id in client.state.DelRunTbl
        ]
        server_result = client.server.search(add_tokens, delete_tokens)

        self.assertEqual(len(server_result.Cand), 2)
        self.assertEqual(len(server_result.Dead), 1)
        filtered = client.client_filter(server_result.Cand, server_result.Dead)
        self.assertEqual(filtered.ids, ["d1"])
        self.assertEqual(filtered.killed_count, 1)

    def test_merge_removes_old_runs_fresh_run_id_and_preserves_query(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a"], "d2": ["a"]})
        before = client.search(["a"])
        old_run_ids = list(client.state.RunTbl)

        new_add_run_id, new_delete_run_id = client.merge(old_run_ids, [])

        self.assertIsNotNone(new_add_run_id)
        self.assertIsNone(new_delete_run_id)
        self.assertNotIn(new_add_run_id, old_run_ids)
        for run_id in old_run_ids:
            self.assertNotIn(run_id, client.state.RunTbl)
            self.assertNotIn(run_id, client.server.add_runs)
        self.assertEqual(client.search(["a"]), before)

    def test_repeated_logical_updates_do_not_reuse_run_id_or_run_key_id(self):
        client = DynDorisClient(buffer_capacity=10)
        client.setup({"d1": ["a"]})

        client.update("add", "b", "d1")
        first_add_run = client.flush_add_buffer()
        first_delete_run = client.flush_delete_buffer()

        client.update("delete", "b", "d1")
        second_add_run = client.flush_add_buffer()
        second_delete_run = client.flush_delete_buffer()

        run_ids = {first_add_run, first_delete_run, second_add_run, second_delete_run}
        self.assertEqual(len(run_ids), 4)

        key_ids = [
            client.server.get_run(run_id).run_key_id
            for run_id in run_ids
            if run_id is not None
        ]
        self.assertEqual(len(key_ids), len(set(key_ids)))


if __name__ == "__main__":
    unittest.main()
