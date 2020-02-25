#!/bin/env python3

import logging, threading, time, random, uuid, threading, requests, json, sys, signal, string

logged_in_users_list = []


logging.getLogger("urllib3").setLevel(logging.ERROR)
LOGGING_FORMAT = 't="%(asctime)-15s" lvl=%(levelname)s func="%(funcName)s" client="%(clientip)s" uid=%(uid)s user="%(user)s" msg="%(message)s"'
logging.basicConfig(format=LOGGING_FORMAT)


CONTINUE_RUNNING = True

CONFIG = json.load(open('config.json'))


def _update_logger():
  lgr = logging.getLogger()
  lgr.setLevel(logging.getLevelName(CONFIG['log_level']))
  return lgr

LOGGED_IN_USERS = []
logger = _update_logger()

def randomString(stringLength=3):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))
  

def login():
  time.sleep(CONFIG['sleep_time'])
  logging_in_user_name_template = CONFIG['users_list'][random.randrange(0, len(CONFIG['users_list']))]
  logging_in_user = logging_in_user_name_template.format(name=randomString())
  users_ip_cidr = CONFIG['ip_address_list'][random.randrange(0, len(CONFIG['ip_address_list']))]
  users_ip = users_ip_cidr.format(random.randrange(1,255))
  metadata = {'clientip': users_ip, 'user' : logging_in_user, 'uid': str(uuid.uuid1())}
  rand = random.random()
  if CONFIG['login_unauthorized_chance'] > rand:
    logger.warning('unauthorized', extra=metadata)
  elif CONFIG['login_connection_reset_error_chance'] > rand:
    logger.error('connection reset', extra=metadata)
  else:
    logger.info('loggin successfull', extra=metadata)
    metadata['cart'] = []
    LOGGED_IN_USERS.append(metadata)

  
def get_item():
  return random.randrange(0, 1000)


def addToCart():
  for usr in LOGGED_IN_USERS:
    time.sleep(CONFIG['sleep_time'])
    should_add_something_to_cart = CONFIG['should_add_something_to_cart_chance'] > random.random()
    if not(should_add_something_to_cart):
      continue
    item = get_item()
    logger.debug('attempting to add item %s to cart', item, extra=usr)
    if CONFIG['item_out_of_stock_chance'] > random.random():
      logger.warning("item %s out of stock", item, extra=usr)
    else:
      logger.info('added item: %s to cart', item, extra=usr)
      usr['cart'].append(item)

def checkout():
  for usr in LOGGED_IN_USERS:
    time.sleep(CONFIG['sleep_time'])
    should_checkout = CONFIG['should_checkout_chance'] > random.random()
    if not(should_checkout):
      # logger.debug("user is not checking out", extra=usr)
      continue
    logger.debug("user is about to checkout", extra=usr)
    if CONFIG['checkout_connection_reset_error_chance'] > random.random():
      logger.error("connection reset", extra=usr)
    elif CONFIG['credit_card_not_valid_chance'] > random.random():
      logger.error("credit card not valid", extra=usr)
    else:
      logger.info("user checked out", extra=usr)
      usr['cart'] = []



def logout():
  time.sleep(CONFIG['sleep_time'])
  user_should_logout = CONFIG['number_of_users_online'] < len(LOGGED_IN_USERS)
  if not(user_should_logout):
    return
  usr = LOGGED_IN_USERS[random.randrange(0, len(LOGGED_IN_USERS))]
  logger.info("user logged out", extra=usr)
  LOGGED_IN_USERS.remove(usr)


def run():
  try:
    while True:
      login()
      addToCart()
      checkout()
      logout()
  except KeyboardInterrupt:
    global CONTINUE_RUNNING
    CONTINUE_RUNNING = False
    print("exiting in 30sec or less")
    sys.exit()

################################# config update from the web #################################

def config_changer_thread():
  print("running config changer")
  global CONFIG
  while True:
    if not(CONTINUE_RUNNING):
      return
    try:
      res = requests.get('https://raw.githubusercontent.com/vbichov/log_generator/master/config.json')
      res.raise_for_status()
      res_json = res.json()
      print("attempting to change config")
      CONFIG = res_json
      if res_json['change_logger'] == True:
        global logger
        logger = _update_logger()
    except:
      print("could not get config change")
    finally:
      time.sleep(30)

threading.Thread(target=config_changer_thread).start()
################################# config update from the web #################################






if __name__ == "__main__":
    run()