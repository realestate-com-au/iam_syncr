def listify(dct, key):
    """Make sure a key in this dct is a list"""
    if key not in dct:
        dct[key] = []
    elif not isinstance(dct[key], list):
        dct[key] = [dct[key]]
    return dct[key]

def listified(dct, key):
    """
    Yield the items under key

    If item is not a list, then just yield that item
    """
    if key in dct:
        if isinstance(dct[key], list):
            for thing in dct[key]:
                yield thing
        else:
            yield dct[key]

def as_list(item):
    """Yields the items in the item unless not a list, in which case just yield the item"""
    if isinstance(item, list):
        for thing in item:
            yield thing
    else:
        yield item

