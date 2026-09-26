import { Logger } from '@nestjs/common';

// Los casos de uso registran cada paso; en los tests solo estorban. Activar con TEST_LOGS=1.
if (!process.env.TEST_LOGS) Logger.overrideLogger(false);
