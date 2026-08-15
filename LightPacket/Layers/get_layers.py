# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


def get_all_layers(layer) -> list:

    layers = []
    current = layer
    while current:
        layers.append(current)
        try:
            current = current.payload
        except AttributeError:
            break

    return layers

def printpc(packet) -> None:
    layers = get_all_layers(packet)
    for layer in layers:
        print(layer.__class__.__name__)


def haslayer(packet, layer) -> bool:
    layers = get_all_layers(packet)
    for i in layers:
        if i.__class__.__name__ == layer:
            return True
    return False