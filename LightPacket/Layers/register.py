# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

class ProtocolRegistry:
    def __init__(self):
        self.bindings = {
            "ethertype": {},
            "dsap_ssap": {},
            "ppp_proto": {},
            "wifi_subtype": {},
        }
        self.layers = {}

    def register(self, layer_name, parser, binding_type, binding_value, unique_field=None):
        """
        Register a custom protocol layer.

        Args:
            layer_name: String name of the layer
            parser: Callable that takes raw bytes and returns a BaseLayer object
            binding_type: 'ethertype', 'dsap_ssap', 'ppp_proto', 'wifi_subtype'
            binding_value: Value that triggers this parser (int or tuple)
            unique_field: Field name to store in the layer (e.g., 'ethertype', 'proto')
        """
        self.bindings[binding_type][binding_value] = {
            'name': layer_name,
            'parser': parser,
            'unique_field': unique_field
        }
        self.layers[layer_name] = parser

    def get_parser(self, binding_type, binding_value):
        """Get parser for a given binding type and value."""
        return self.bindings.get(binding_type, {}).get(binding_value)

    def unregister(self, binding_type, binding_value):
        """Unregister a protocol."""
        if binding_type in self.bindings:
            self.bindings[binding_type].pop(binding_value, None)

registry = ProtocolRegistry()

def bind_layer(layer_name, parser, binding_type, binding_value, unique_field=None):
    registry.register(layer_name, parser, binding_type, binding_value, unique_field)