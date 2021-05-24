import argparse

from tracert_as.services.route_tracer import Traceroute


def prepare_args():
    parser.add_argument('hostname', type=str, help="Hostname to trace")
    parser.add_argument("--ttl", type=int, help="Max hops count", default=25)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    prepare_args()
    args = parser.parse_args()
    traceroute = Traceroute(args.hostname, args.ttl)
    trace_result = traceroute.make_trace()
    for i in range(len(trace_result)):
        if trace_result[i] is None:
            print(f"{i + 1}. *")
        else:
            print(f"{i + 1}. {trace_result[i]}")
