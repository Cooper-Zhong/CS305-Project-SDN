from queue import PriorityQueue

MAX_V = 1000
inf = 100000


class Graph:
    def __init__(self):
        self.nodes = []
        self.edges = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]
        self.port = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]
        self.vis = []

    def add_edge(self, src, dst, weight, port):
        self.edges[src][dst] = weight
        self.port[src][dst] = port

    def delete_edge(self, src, dst):
        self.edges[src][dst] = -1

    def add_node(self, dpid):
        self.nodes.append(dpid)

    def delete_node(self, dpid):
        self.nodes.remove(dpid)

    def dijkstra(self, start):
        self.vis = []
        D = {v: inf for v in self.nodes}
        D[start] = 0
        q = PriorityQueue()
        q.put((0, start))
        pre = {}
        while not q.empty():
            (dis, x) = q.get()
            self.vis.append(x)
            for y in self.nodes:
                if self.edges[x][y] != -1 and y not in self.vis:
                    if D[x] + self.edges[x][y] < D[y]:
                        D[y] = D[x] + self.edges[x][y]
                        q.put((D[y], y))
                        pre[y] = x
        paths = {}
        for dst in self.nodes:
            path = []
            t = dst
            while t != start:
                path.append(t)
                t = pre[t]
            path.append(start)
            path.reverse()
            paths[dst] = path
        return D, paths

    def shortest_path(self, src, dst):
        D, paths = self.dijkstra(src)
        path = paths[dst]
        path_len = len(path)
        return path, path_len
