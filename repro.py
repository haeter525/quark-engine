from quark.evaluator.pyeval import PyEval
from quark.core.struct.registerobject import RegisterObject
from quark.core.struct.valuenode import Primitive

p = PyEval(None)
# populate registers with missing types
for idx, val in [(13,'0'), (11,'1'), (12,'2')]:
    p.table_obj.insert(idx, RegisterObject(Primitive(val, ""), value_type=""))

ins = ['filled-new-array', 'v13', 'v11', 'v12', 'new-array()[I']

print('Before invoke, argIdxWithoutType expectation: 0..')
try:
    p._invoke(ins)
    print('Completed without error')
except Exception as e:
    print('Exception', type(e).__name__, e)
