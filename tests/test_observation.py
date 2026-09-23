import unittest
from queue import Queue
from threading import Event
from agent_hooks_protocol.lifecycle import dispatch_observations

class ObservationTests(unittest.TestCase):
    def test_remaining_interceptors_and_explicit_observers_only(self):
        received, release = Queue(), Event()
        prepared = []
        subscriptions = [{'id': i, 'mode': mode} for i, mode in [('called', 'intercept'), ('remaining', 'intercept'), ('explicit', 'observe')]]
        event = {'id': 'same', 'source': 'urn:test', 'type': 'tool.before', 'secret': 'effective'}
        def prepare(event, sub):
            prepared.append(sub['id'])
            event.pop('secret')  # Simulated permission projection precedes upload/notify.
            return event
        def notify(message):
            received.put(message)
            release.wait(2)  # Processing never delays the caller or another observer.
        dispatch_observations(event, subscriptions, {'called'}, prepare, notify)
        try:
            notes = [received.get(timeout=1), received.get(timeout=1)]
            self.assertEqual(set(prepared), {'remaining', 'explicit'})
            for note in notes:
                self.assertEqual(set(note), {'jsonrpc', 'method', 'params'})
                self.assertEqual(set(note['params']), {'protocolVersion', 'event'})
                self.assertEqual(note['params']['event']['id'], 'same')
                self.assertNotIn('secret', note['params']['event'])
            self.assertEqual(event['secret'], 'effective')
            self.assertTrue(received.empty())
        finally:
            release.set()
