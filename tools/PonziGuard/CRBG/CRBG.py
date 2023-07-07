import os
from gensim.models import Doc2Vec
from gensim.utils import simple_preprocess
from op_des import opcode_in_out, opcode_des

path = "/home/lrc/myproject/open-source/ponziguard/CRBG/CRBG_output_onehot/"
output_dir = "/home/lrc/myproject/open-source/ponziguard/CRBG/CRBG_output"
model_dir = "/home/lrc/myproject/open-source/ponziguard/CRBG/model/yourModel/Model.bin"

model = Doc2Vec.load(model_dir)
graphs = os.listdir(path)
print(graphs)
for graph in graphs:
    with open(path + graph) as f:
        ctx = []
        lines = f.readlines()
        for line in lines:
            if '[' in line[0]:
                line = line.split('[')[1].split(']')[0].split(' ')
                index = 0
                for i in range(len(line)):
                    if line[i] == '1':
                        index = i
                        break
                des = opcode_des[index]
                _in, _out = opcode_in_out[index][0], opcode_in_out[index][1]
                preprocessed_des = simple_preprocess(des)
                vector = model.infer_vector(preprocessed_des)
                vct =str(vector.tolist()).strip(']') + ', ' + str(_in) + ', ' +str(_out)+ ']\n'
                ctx.append(vct)
            else:
                ctx.append(line)

    with open(output_dir + '/' + graph, 'w')as f:
        for line in ctx:
            f.write(line)