import { AuthUserPayload } from './database';

declare global {
    namespace Express {
        interface Request {
            user?: AuthUserPayload;
        }
    }
}
