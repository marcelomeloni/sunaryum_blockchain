from apscheduler.schedulers.background import BackgroundScheduler
import time
import logging

class FastScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
            
    def schedule_job(self, job, interval=10):
        self.scheduler.add_job(job, 'interval', seconds=interval)
        logging.info(f"Tarefa agendada a cada {interval}s")
    
    def run_forever(self):
        self.scheduler.start()
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            self.scheduler.shutdown()
            logging.info("Agendador encerrado")