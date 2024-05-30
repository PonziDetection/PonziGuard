# -*- coding: utf-8 -*-
import os
from op_des import opcode_in_out, opcode_des, OpList
import networkx as nx
import numpy as np

from gensim.models import Doc2Vec
from gensim.utils import simple_preprocess

# print('opcode_des:{}'.format(len(opcode_des)))

path = "/home/lrc/myproject/node_data_dapp"
model_dir = "/home/lrc/myproject/model/doc2vec.bin"
model = Doc2Vec.load(model_dir)
output_dir = "/home/lrc/myproject/node_data_dapp_CRBG"


class Node:
    def __init__(self, op, index, attr, simple_attr):
        self.op = op
        self.index = index
        self.attr = attr
        self.simple_attr = simple_attr
        

class Graph:
    def __init__(self):
        self.nodes = []

    def add_node(self, node):
        self.nodes.append(node)

    def split_by_index(self, index):
        subgraph1 = Graph()
        subgraph2 = Graph()
        for node in self.nodes:
            if node.index <= index:
                subgraph1.add_node(node)
            else:
                subgraph2.add_node(node)
        return subgraph1, subgraph2
    
class Egde:
    def __init__(self, src, des, index, attr):
        self.src = src
        self.des = des
        self.index = index
        self.attr = attr


def read_single(graph):
    gs = []
    edges = []
    with open(graph) as f:
        ctx = []
        lines = f.readlines()
        g = Graph()
        node_index = 0
        for line in lines:

            if '[' in line[0]:
                line = line.split('[')[1].split(']')[0].split(' ')
                index = 0
                for i in range(len(line)):
                    if line[i] == '1':
                        index = i
                        break
                
                simple_attr = [0] * 72
                simple_attr[index] = 1
                op = OpList[index]
                des = opcode_des[index]
                _in, _out = opcode_in_out[index][0], opcode_in_out[index][1]
                arr = np.array([_in, _out])
                # print(arr)
                preprocessed_des = simple_preprocess(des)
                vector = model.infer_vector(preprocessed_des)
                # vector = np.round(vector, decimals=4)
                vec = np.append(vector, arr)
                vec = np.round(vec, decimals=4)
                node = Node(op, node_index, vec, simple_attr)
                g.add_node(node)
                node_index += 1

            if 'src' in line:
                src = int(line.split(' ')[0].split(':')[1])
                des = int(line.split(' ')[1].split(':')[1])
                attr = line.split('attr:')[1]
                line = attr.split('[')[1].split(']')[0].split(' ')
                # print(line)
                index = -1
                for i in range(len(line)):
                    if line[i] == '1':
                        index = i
                        break
                if index != -1:
                    edge_attr = [0] * 15
                    edge_attr[index] = 1
                    edge = Egde(src, des, index, edge_attr)
                    edges.append(edge)
    
    gs.append(g)
    # show_egdes(edges)
    return gs, edges



def split_graphs(gs, edges):

    for edge in edges:
        if edge.index == 14:
            g = gs[-1]
            split_index = edge.src
            # print("split point:{}".format(split_index))

            # start = g.nodes[0].index
            # end = g.nodes[-1].index
            # print(f'from {start} to {end}')

            g1, g2 = g.split_by_index(split_index)
            gs = gs[:-1]
            gs.append(g1)
            gs.append(g2)

    print('raw graphs:')
    show_graphs(gs)
    return gs


def proun_graphs(gs, edges):
    data_edge = []

    for edge in edges:
        if edge.index == 6 or edge.index == 11:
            data_edge.append(edge.src)
            data_edge.append(edge.des)

    for g in gs:
        is_SSTORE = False
        is_CALLVALUE = False
        is_CALLER = False
        is_CALL = False
        is_compare = False

        for node in g.nodes:
            if node.op == 'SSTORE':
                is_SSTORE = True
            if node.op == 'CALLVALUE':
                is_CALLVALUE = True
            if node.op == 'CALLER':
                is_CALLER = True
            if node.op == 'CALL':
                is_CALL = True
            if node.op in ['LT','GT','SLT','SGT','EQ']:
                if node.index in data_edge:
                    is_compare = True
        if is_SSTORE == False:
            msg = 'no sstore'
            try:
                gs, edges = renew_graph(g,gs,edges,msg)
            # print('\n')
            # print("remove node(no sstore): from {} to {}".format(g.nodes[0].index, g.nodes[-1].index))
            except:
                print('renew fail\n')
        
        if is_CALLVALUE and is_CALLER and is_CALL and is_compare == False:
            msg = 'no ponzi behavior'
            try:
                gs, edges = renew_graph(g,gs,edges,msg)
            # print('\n')
            # print("remove node(no ponzi behavior): from {} to {}".format(g.nodes[0].index, g.nodes[-1].index))
            except:
                print('renew fail\n')
    return gs, edges


def show_graphs(gs):
    for index, g in enumerate(gs):
        start = g.nodes[0].index
        end = g.nodes[-1].index
        print("node {}: ({}, {})".format(index, start, end))
        # print('node vect:{}'.format(g.nodes[5].attr))


def show_egdes(edges):
    for edge in edges:
        # print(f'edge from {edge.src} to {edge.des}')
        print("edge from {} to {}".format(edge.src, edge.des))


def renew_graph(g, gs, edges, msg):

    edge2del = []

    print("\nremove node ({}):node{} ({}, {})".format(msg, gs.index(g), g.nodes[0].index, g.nodes[-1].index))
    gs.remove(g)
    start = g.nodes[0].index
    end = g.nodes[-1].index
    # print('start={} end={}\n'.format(start, end))
    sub = end - start + 1
    for _g in gs:
        if _g.nodes[0].index > end:
            for node in _g.nodes:
                node.index = node.index - sub

    # show_egdes(edges)


    for edge in edges:
        # if edge.src in range(start, end+1) or edge.des in range(start, end+1):
        # print('src={} des={}\n'.format(edge.src, edge.des))

        if (start <= edge.src <= end) or (start <= edge.des <= end):
            edge2del.append(edge)
            # edges.remove(edge)
        #     print('remove src={} des={}\n'.format(edge.src, edge.des))
        # else:
        #     print('not remove src={} des={}\n'.format(edge.src, edge.des))
        
    for it in edge2del:
        edges.remove(it)
        
    for edge in edges:    
        if edge.src > end:
            edge.src = edge.src - sub
        if edge.des > end:
            edge.des = edge.des - sub

    return gs, edges

def cosine_similarity(v1, v2):
    # 计算余弦相似度
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    similarity = dot_product / (norm_v1 * norm_v2)
    return similarity

def graph_feature_similarity(G1, G2):
    # 计算节点相似度的平均值
    node_similarities = []
    for node1 in G1.nodes(data=True):
        for node2 in G2.nodes(data=True):
            node_feature1 = node1[1]['attribute']
            node_feature2 = node2[1]['attribute']
            node_similarities.append(cosine_similarity(node_feature1, node_feature2))
    avg_node_similarity = sum(node_similarities) / len(node_similarities)

    # 计算边相似度的平均值
    edge_similarities = []
    for edge1 in G1.edges(data=True):
        for edge2 in G2.edges(data=True):
            edge_feature1 = edge1[2]['attribute']
            edge_feature2 = edge2[2]['attribute']
            edge_similarities.append(cosine_similarity(edge_feature1, edge_feature2))
    avg_edge_similarity = sum(edge_similarities) / len(edge_similarities)

    # 综合节点和边相似度，可以根据具体情况赋予权重
    graph_similarity = 1 * avg_node_similarity + 0 * avg_edge_similarity
    # graph_similarity = avg_node_similarity

    return graph_similarity


def cosine_similarity2(v1, v2):
    # 计算余弦相似度
    dot_product = np.dot(v1, v2)
    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)
    similarity = dot_product / (norm_v1 * norm_v2)
    return similarity

def graph_feature_similarity2(G1, G2):
    # 提取图的节点和边特征
    node_features_G1 = [node[1]['attribute'] for node in G1.nodes(data=True)]
    node_features_G2 = [node[1]['attribute'] for node in G2.nodes(data=True)]
    edge_features_G1 = [edge[2]['attribute'] for edge in G1.edges(data=True)]
    edge_features_G2 = [edge[2]['attribute'] for edge in G2.edges(data=True)]

    # 计算节点特征的平均相似度
    avg_node_similarity = np.mean([cosine_similarity2(feature_G1, feature_G2) for feature_G1, feature_G2 in zip(node_features_G1, node_features_G2)])

    # 计算边特征的平均相似度
    avg_edge_similarity = np.mean([cosine_similarity2(feature_G1, feature_G2) for feature_G1, feature_G2 in zip(edge_features_G1, edge_features_G2)])

    # 综合节点和边特征的相似度
    graph_similarity = 0.8 * avg_node_similarity + 0.2 * avg_edge_similarity

    return round(graph_similarity, 2)



class GP():
    def __init__(self, i, j, g1, g2):
        self.i = i
        self.j = j
        self.g1 = g1
        self.g2 = g2





def renew_dic(merged_dict,n):
    key2del = []
    for index, key in enumerate(merged_dict):
        if index == n:
            target_key = key

        if index > n:
            if key in merged_dict[target_key]:
                key2del.append(key)
                for v in merged_dict[key]:
                    if v not in merged_dict[target_key]:
                        merged_dict[target_key].append(v)
            
    for key in key2del:
        del merged_dict[key]
    return merged_dict



def proun_similar(turple_lst, gs, edges):
    merged_dict = {}
    for turple in turple_lst:
        if turple[0] not in merged_dict:
            merged_dict[turple[0]] = []
            merged_dict[turple[0]].append(turple[1])
        else:
            merged_dict[turple[0]].append(turple[1])

    k = 0
    while len(merged_dict) >= k+2:
        merged_dict = renew_dic(merged_dict, k)
        k += 1

    proun_lst = []
    for key in merged_dict:
        lst = merged_dict[key]
        for it in lst:
            proun_lst.append(it)

    print('proun_lst: {}'.format(proun_lst))

    for index, proun in enumerate(proun_lst):
        g = gs[proun-index]
        msg = 'similar'
        try:
            gs, edges = renew_graph(g,gs,edges,msg)
        except:
            print('renew fail\n')

    return gs, edges



def deal_single(file):
    gs, edges = read_single(file)
    if gs == [] or edges == []:
        return
    gs = split_graphs(gs,edges)
    # show_egdes(edges)
    gs, edges = proun_graphs(gs,edges)

    GS = []
    for g in gs:
        G = nx.Graph()
        all_index = []
        for node in g.nodes:
            # G.add_nodes_from([(node.index, {'attribute': node.simple_attr})])
            G.add_nodes_from([(node.index, {'attribute': node.simple_attr})])
            # G.add_nodes_from([(node.index)])


            all_index.append(node.index)
        for edge in edges:
            if edge.src in all_index and edge.des in all_index:
                G.add_edges_from([(edge.src, edge.des, {'attribute': edge.attr})])
        GS.append(G)
    # print('len(GS):{}'.format(len(GS)))


    # threshold = 0.8
    pairs = []
    for i in range(len(GS)):
        for j in range(i + 1, len(GS)):
            gp =GP(i,j,GS[i],GS[j])
            pairs.append(gp)

    # print('combinations:{}'.format(len(pairs)))
    similar = []
    print('\nsimilarity of nodes:')
    for gp in pairs:
        similarity = graph_feature_similarity2(gp.g1, gp.g2)
        print("node {} and node {}: {}:".format(gp.i,gp.j,similarity))
        if similarity > 0.75:
            similar.append((gp.i,gp.j))
    print('\nsimilar nodes:{}'.format(similar))

    gs, edges = proun_similar(similar, gs, edges)

    print('\nresult of proun_graphs:')

    show_graphs(gs)
    
    contract = file.split('/')[-1].split('.')[0]
    with open(output_dir + '/' + contract + '.txt', 'w')as f:
        f.write('Contract {}:\n'.format(contract))
        f.write('Node:\n')
        for g in gs:
            for node in g.nodes:
                f.write(str(node.attr.tolist()))
                f.write('\n')
        f.write('Edge:\n')
        for edge in edges:
            f.write('src:{} dest:{} attr:{}\n'.format(edge.src, edge.des, edge.attr))


def main():
    files = os.listdir(path)
    
    for file_name in files:
        file = path + '/' + file_name
        print('dealing with {}\n'.format(file))
        deal_single(file)


    # deal_single('/home/lrc/myproject/open-source/test.txt')
if __name__ == '__main__':
    main()