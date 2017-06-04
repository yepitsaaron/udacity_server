from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, Item, User

engine = create_engine('postgresql://catalog:catalog@localhost:5432/catalog')
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
User1 = User(name="Legendary Guitarist", email="srv@rip.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()

# Category for guitars
category1 = Category(user_id=1, name="Guitars")

session.add(category1)
session.commit()

Item1 = Item(user_id=1, name="Taylor 414ce", description="Taylor 414ce description",
                     price="$2199", category=category1)

session.add(Item1)
session.commit()


Item2 = Item(user_id=1, name="Martin OMJM", description="Martin OMJM description",
                     price="$3499", category=category1)

session.add(Item2)
session.commit()