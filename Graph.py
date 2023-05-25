import copy
from queue import PriorityQueue
from queue import Queue
MAX_V = 1000
inf = 100000


class Graph:
    def __init__(self):
        self.nodes = []
        self.edges = [[inf for i in range(MAX_V)] for j in range(MAX_V)]
        self.port = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]
        self.port_on = [[False for i in range(MAX_V)] for j in range(MAX_V)]
        self.vis = []
        self.paths = [[{} for i in range(MAX_V)] for j in range(MAX_V)]

    def add_edge(self, src, dst, weight, port):
        self.edges[src][dst] = weight
        self.port[src][dst] = port
        self.port_on[src][port] = True

    def delete_edge(self, src, dst):
        self.edges[src][dst] = inf
        self.port[src][dst] = -1

    def add_node(self, dpid):
        self.nodes.append(dpid)

    def delete_node(self, dpid):
        self.nodes.remove(dpid)

    def dijkstra(self, src):
        self.vis = []
        D = {v: inf for v in self.nodes}
        D[src] = 0
        q = PriorityQueue()
        q.put((0, src))
        pre = {}
        while not q.empty():
            (dis, x) = q.get()
            self.vis.append(x)
            for y in self.nodes:
                if self.edges[x][y] != inf and self.port_on[x][self.port[x][y]] and y not in self.vis:
                    if D[x] + self.edges[x][y] < D[y]:
                        D[y] = D[x] + self.edges[x][y]
                        q.put((D[y], y))
                        pre[y] = x
        for dst in self.nodes:
            if D[dst] == inf:
                continue
            path = []
            t = dst
            while t != src:
                path.append(t)
                t = pre[t]
            path.append(src)
            path.reverse()
            self.paths[src][dst] = path

    def floyd(self):
        temp = [[-1 for i in range(MAX_V)] for j in range(MAX_V)]
        dis = copy.deepcopy(self.edges)
        for i in self.nodes:
            dis[i][i] = 0
        for i in self.nodes:
            for j in self.nodes:
                if self.edges[i][j] != inf and not self.port_on[i][self.port[i][j]]:
                    dis[i][j] = inf
        for k in self.nodes:
            for i in self.nodes:
                for j in self.nodes:
                    if dis[i][j] > dis[i][k] + dis[k][j]:
                        dis[i][j] = dis[i][k] + dis[k][j]
                        temp[i][j] = k
        for i in self.nodes:
            for j in self.nodes:
                if dis[i][j] == inf:
                    continue
                self.paths[i][j] = self.floyd_print_path(temp, i, j)

    def floyd_print_path(self, temp, s, t):
        if s == t:
            return
        if temp[s][t] == -1:
            return [s, t]
        path1 = self.floyd_print_path(temp, s, temp[s][t])
        path1.remove(temp[s][t])
        if not path1:
            path1 = []
        path2 = self.floyd_print_path(temp, temp[s][t], t)
        path = path1 + path2
        return path

    def SPFA(self, src):
        self.vis = []
        pre = {}
        q = Queue()
        D = {v: inf for v in self.nodes}
        q.put(src)
        D[src] = 0
        self.vis.append(src)
        while not q.empty():
            x = q.get()
            self.vis.remove(x)
            for y in self.nodes:
                if self.edges[x][y] != inf and self.port_on[x][self.port[x][y]] and y not in self.vis:
                    if D[x] + self.edges[x][y] < D[y]:
                        D[y] = D[x] + self.edges[x][y]
                        if y in self.vis:
                            continue
                        q.put(y)
                        pre[y] = x
                        self.vis.append(y)
        for dst in self.nodes:
            if D[dst] == inf:
                continue
            path = []
            t = dst
            while t != src:
                path.append(t)
                t = pre[t]
            path.append(src)
            path.reverse()
            self.paths[src][dst] = path

    def shortest_path(self, src, dst):
        if dst not in self.nodes:
            return [], -1
        if not self.paths[src][dst]:
            return [], -1
        path = self.paths[src][dst]
        path_len = len(path)
        return path, path_len
