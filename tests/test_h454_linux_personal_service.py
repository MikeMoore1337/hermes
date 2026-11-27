"""A personal worker must run under its dedicated no-capability unit."""
import unittest

from scripts.h454_linux_personal_service import kernel_authorized


def status(uid=1000):
    return ('Name:\tfixture\nNoNewPrivs:\t1\n'
            f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n'
            'CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n'
            'CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n')


class KernelAuthorizationTests(unittest.TestCase):
    def test_dedicated_nonroot_unit_and_no_capabilities_are_required(self):
        cgroup = '0::/system.slice/hermes-commander-personal-yfc.service\n'
        self.assertTrue(kernel_authorized(status(), cgroup, 'yfc-vps', 1000))
        for bad, group, target, uid in (
            (status().replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'), cgroup, 'yfc-vps', 1000),
            (status().replace('CapEff:\t0000000000000000', 'CapEff:\t0000000000000001'), cgroup, 'yfc-vps', 1000),
            (status() + 'Uid:\t1000\t1000\t1000\t1000\n', cgroup, 'yfc-vps', 1000),
            (status(), cgroup, 'hermes-vps', 1000),
            (status(), '0::/user.slice\n', 'yfc-vps', 1000),
            (status(uid=0), cgroup, 'yfc-vps', 0),
        ):
            with self.subTest(target=target, uid=uid):
                self.assertFalse(kernel_authorized(bad, group, target, uid))


if __name__ == '__main__':
    unittest.main()
