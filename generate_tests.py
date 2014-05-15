import ast
import astunparse

module_translations = {
    'requests': 'async_requests'
}

class_translations = {
    'HTTPAdapter': 'AsyncHTTPAdapter',
    'HTTPDigestAuth': 'AsyncHTTPDigestAuth',
    'Response': 'AsyncResponse',
    'Session': 'AsyncSession',
}

methods = ['get', 'head', 'put', 'patch', 'post', 'send', 'request']

assign_template = """
task = asyncio.Task({rhs})
loop = asyncio.get_event_loop()
{lhs} = loop.run_until_complete(task)
""".strip()

expr_template = """
task = asyncio.Task({expr})
loop = asyncio.get_event_loop()
loop.run_until_complete(task)
""".strip()


class TestRequestsTransformer(ast.NodeTransformer):
    def __init__(self):
        self.imported_asyncio = False

    def visit_Import(self, node):
        name = node.names[0].name

        if name in module_translations:
            return ast.Import([ast.alias(module_translations[name], None)])
        else:
            if not self.imported_asyncio:
                self.imported_asyncio = True
                return [ast.Import([ast.alias('asyncio', None)]), node]
            else:
                return node

    def visit_ImportFrom(self, node):
        path = node.module.split('.')
        if path[0] in module_translations:
            module = '.'.join([module_translations[path[0]]] + path[1:])
        else:
            module = node.module

        names = []
        for alias in node.names:
            if alias.name in class_translations:
                names.append(ast.alias(class_translations[alias.name], alias.asname))
            else:
                names.append(alias)

        return ast.ImportFrom(module, names, node.level)

    def visit_Name(self, node):
        if node.id in module_translations:
            return ast.Name(module_translations[node.id], node.ctx)
        elif node.id in class_translations:
            return ast.Name(class_translations[node.id], node.ctx)
        else:
            return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if node.attr in class_translations:
            return ast.Attribute(node.value, class_translations[node.attr], node.ctx)
        else:
            return node

    def visit_Expr(self, node):
        self.generic_visit(node)
        try:
            if node.value.func.attr in methods:
                expr = astunparse.unparse(node)
                new_source = expr_template.format(expr=expr)
                new_node = ast.parse(new_source)
                return new_node
            else:
                return node
        except AttributeError:
            return node

    def visit_Assign(self, node):
        self.generic_visit(node)
        try:
            if node.value.func.attr in methods and \
                    astunparse.unparse(node.value.func).strip() != 'os.environ.get':
                lhs = node.targets[0].id
                rhs = astunparse.unparse(node.value).strip()
                new_source = assign_template.format(lhs=lhs, rhs=rhs)
                new_node = ast.parse(new_source)
                return new_node
            else:
                return node
        except AttributeError:
            return node

if __name__ == '__main__':
    with open('test_requests.py') as f:
        source = f.read()

    tree = ast.parse(source)

    TestRequestsTransformer().visit(tree)

    with open('test_async_requests.py', 'w') as f:
        f.write(astunparse.unparse(tree))

    print('Generated test_async_requests.py')
    print('Manual tweaks required for:')
    print('  test_basicauth_with_netrc')
    print('  test_prepared_request_hook')
