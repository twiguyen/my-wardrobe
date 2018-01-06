from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, ClothesType, ClothingItem, User

engine = create_engine('sqlite:///wardrobe.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="JenBot", email="JenBot@FakeEmail.com")
session.add(User1)
session.commit()

# Section for Tops
clothesType1 = ClothesType(name="Tops")

session.add(clothesType1)
session.commit()


clothingItem1 = ClothingItem(name="Scuba Knit Halter Neck Top",
                             description="Glittering beads lend " +
                             "cocktail-hour sparkle to this halter top " +
                             "punctuated with keyholes at the front and " +
                             "back.",
                             clothesType=clothesType1, user=User1)

session.add(clothingItem1)
session.commit()

# Section for Sweaters
clothesType2 = ClothesType(name="Sweaters")

session.add(clothesType2)
session.commit()


clothingItem2 = ClothingItem(name="Textured Boucle Lace-Up Sweater",
                             description="Keep your look relaxed yet chic " +
                             "in this textured sweater finished with " +
                             "unexpected lace-up seams.",
                             clothesType=clothesType2, user=User1)

session.add(clothingItem2)
session.commit()

# Section for Outerwear
clothesType3 = ClothesType(name="Outerwear")

session.add(clothesType3)
session.commit()


clothingItem3 = ClothingItem(name="Wool Blend Coat with Faux Fur Collar",
                             description="Thanks to its luxe faux-fur collar" +
                             " and its flattering fit-and-flare silhouette, " +
                             "this wool blend coat will keep you warm and " +
                             "stylish all season long.",
                             clothesType=clothesType3, user=User1)

session.add(clothingItem3)
session.commit()

# Section for Bottoms

clothesType4 = ClothesType(name="Bottoms")

session.add(clothesType4)
session.commit()

clothingItem4 = ClothingItem(name="Ponte Slim Leg Pant",
                             description="A pair of slim-leg, ponte knit " +
                             " pants are the ideal basic for chic " +
                             "day-to-play style.",
                             clothesType=clothesType4, user=User1)

session.add(clothingItem4)
session.commit()

# Section for Dresses

clothesType5 = ClothesType(name="Dresses")

session.add(clothesType5)
session.commit()

clothingItem5 = ClothingItem(name="3D Floral Cocktail Dress",
                             description="3D floral appliques add gorgeous " +
                             "dimension to this fanciful cocktail dress " +
                             "designed with a full tulle skirt.",
                             clothesType=clothesType5, user=User1)

session.add(clothingItem5)
session.commit()

# Section for Shoes

clothesType6 = ClothesType(name="Shoes")

session.add(clothesType6)
session.commit()

clothingItem6 = ClothingItem(name="Lace & Satin Peep Toe Shootie",
                             description="An exquisite peep toe shootie " +
                             "is finished with romantic lace and luminous" +
                             "satin for a 'wow' factor look that thrills.",
                             clothesType=clothesType6, user=User1)

session.add(clothingItem6)
session.commit()

# Section for Accessories

clothesType7 = ClothesType(name="Accessories")

session.add(clothesType7)
session.commit()

clothingItem7 = ClothingItem(name="Saffiano Leather-Like Satchel",
                             description="Perfect for every day of the " +
                             "week, a structured satchel that compliments" +
                             " any look.",
                             clothesType=clothesType7, user=User1)

session.add(clothingItem7)
session.commit()

print "added clothes items!"
