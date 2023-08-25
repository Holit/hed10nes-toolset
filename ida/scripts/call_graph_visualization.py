import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
# 读取文件数据并创建有向图
def create_directed_graph_from_file(filename):
    G = nx.DiGraph()
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                source, target = line.split(',')
                G.add_edge(source, target)
    return G

# 绘制有向图
def draw_directed_graph(G):
    # 创建 pyvis 的网络对象
    nt = Network(notebook=True,directed =True)
    nt.from_nx(G)
    #nt.nodes["shape"] = "box"  # 节点形状为矩形
    #nt.edges.arrows.to_type = "arrow" # 添加箭头
    nt.show("function_flow.html")
    nt.toggle_physics(False)
    nt.barnes_hut(gravity=-8000, spring_length=1000, spring_strength=0.001)
    #pos = nx.random_layout(G)  # 或者使用其他层次布局算法
    #nx.draw_networkx(G, pos, with_labels=True, node_size=50, node_color="skyblue", font_size=6, font_color="red", font_weight="bold")
    #plt.title("Directed Graph")
    #plt.show()

if __name__ == "__main__":
    filename = "graph_data1.txt"  # 请将文件名更改为实际的文件名
    directed_graph = create_directed_graph_from_file(filename)
    draw_directed_graph(directed_graph)
