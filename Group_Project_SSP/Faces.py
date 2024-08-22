class Faces:
    # count_id = 0

    def __init__(self, Face):
        # Products.count_id += 1
        self.__Face = Face

    def get_Face(self):
        return self.__Face

    def set_Face(self, Face):
        self.__Face = Face