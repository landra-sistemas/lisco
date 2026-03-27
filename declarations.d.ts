declare module "@landra_sistemas/lisco" {
    import type { Application, NextFunction, Request, Response, Router } from "express";
    import type { Knex } from "knex";

    export interface ServerConfig {
        disableI18nWatcher?: boolean;
        socketio?: boolean;
        cors?: any;
        helmet?: any;
        fileupload?: boolean;
        traceRequests?: boolean;
        prefix?: string;
        compression?: boolean;
        json?: boolean;
    }

    /** Parameters served by /api/config */
    export interface AppConfig {
        appName: string;
        appLogo: string;
    }

    export interface EventHandler {
        emit(event: string, data: any, callback: (error?: Error) => void): boolean;
        on(event: string, handler: (data: any) => void): this;
    }

    export class App {
        /** Inicializa la aplicación con la configuración */
        static init(config?: ServerConfig): Promise<void>;

        /** Arranca el servidor */
        static start(): Promise<void>;

        /** Arranca la runtime CLI */
        static runtime(): void;

        /** Personalización de la instancia de Express */
        static customizeExpress: (app: Application) => void;

        /** Rutas que se cargarán en la aplicación */
        static routes: BaseController[];

        /** Archivos estáticos */
        static statics: Record<string, string>;

        /** Ejecuta acciones solo en el main worker */
        static executeOnlyMain: () => void;

        /** Servidor HTTP */
        static server: any;

        static i18n: I18nLoader;

        static events?: EventHandler;

    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    export class BaseController<T = any> {
        entity?: string;
        service?: new (...args: any[]) => T;
        table?: string;
        schema?: any;
        routes?: Record<string, any>;
        listEntidad(req: Request, res: Response, next: NextFunction): Promise<unknown>;
        getEntidad(req: Request, res: Response, next: NextFunction): Promise<unknown>;
        saveEntidad(req: Request, res: Response, next: NextFunction): Promise<unknown>;
        updateEntidad(req: Request, res: Response, next: NextFunction): Promise<unknown>;
        deleteEntidad(req: Request, res: Response, next: NextFunction): Promise<unknown>;
    }

    export class BaseService<T = any, D extends BaseKnexDao<T> = BaseKnexDao<T>> {
        dao: D;

        constructor(dao: new (...args: any[]) => D);

        list(params?: Record<string, any>): Promise<T[]>;
        loadById(id: string | number): Promise<T>;
        save(data: Partial<T>): Promise<T[]>;
        update(id: string | number, data: Partial<T>): Promise<T[]>;
        delete(id: string | number): Promise<void>;
    }
    export class JsonResponse {
        constructor(success: boolean, data?: any, message?: string, total?: number);
        toJson(): object;
    }

    export class BaseKnexDao<T = any> {
        tableName: string;
        constructor(tableName?: string);
        loadAllData(start: number, limit: number): Promise<T[]>;
        loadFilteredData(filters: Record<string, any>, start: number, limit: number): Promise<T[]>;
        countFilteredData(filters: Record<string, any>): Promise<number>;
        loadById(id: string | number): Promise<T>;
        save(data: T): Promise<T[]>;

        update(id: string | number, data: Partial<T>): Promise<T[]>;
        delete(id: string | number): Promise<void>;
    }

    export class KnexConnector {
        static allowGlobalSearch: boolean;
        static caseInsensitive: boolean;
        static connection: Knex;
        static columnAliases: Record<string, Record<string, string>>;

        static init(config?: Knex.Config): Promise<void>;
        static setColumnAliases(aliases: Record<string, Record<string, string>>): void;

        static test(): Promise<void>;
    }

    export class KnexFilterParser {
        static parseQueryString(builder: Knex.QueryBuilder, queryString: string, tableName: string): Knex.QueryBuilder;
        static parseFilters(builder: Knex.QueryBuilder, filters: Record<string, any>, tableName: string): Knex.QueryBuilder;
        static parseSort(sort: { field: string; direction?: "asc" | "desc" }): string;
    }

    export class IAuthHandler {
        check(request: Request): Promise<boolean>;
        validate(request: Request, username: string, password: string): Promise<boolean>;
    }
    export class CookieAuthHandler extends IAuthHandler {
        constructor(userDao: IUserDao);

        logout(request: Request): Promise<void>;
    }
    export class TokenGenerator {
        constructor(privateKey: string, options?: Record<string, any>);

        sign(payload: Record<string, any>): string;

        verify(token: string): Record<string, any>;

        refresh(token: string): string;
    }

    export class JwtAuthHandler extends IAuthHandler {
        tokenGenerator: TokenGenerator;

        constructor(userDao: IUserDao);
    }

    export class AuthController {
        publicPathsList: string[];
        authHandler: IAuthHandler;
        constructor(publicPathsList: string[], authHandler: IAuthHandler);

        configure(): Router;
        check(req: Request, res: Response, next: NextFunction): Promise<void>;
        loginPost(req: Request, res: Response, next: NextFunction): Promise<void>;
        logout(req: Request, res: Response, next: NextFunction): Promise<void>;
    }

    export class IUserDao<T = any> extends BaseKnexDao<T> {
        findByUsername(username: string): Promise<T | undefined>;
    }

    export class Utils {
        static generateKeys(): { iv: string; secret: string };
        static arrayToLower(arr: string[]): string[];

        static replaceAll(str: string, find: string, replace: string): string;

        static encrypt(text: string): string;
        static decrypt(encrypted: string): string;

        static sleep(ms: number): Promise<void>;

        static flattenObject(obj: Record<string, any>): Record<string, any>;
        static unflatten(obj: Record<string, any>): Record<string, any>;
    }

    export class I18nLoader {
        watcher: Record<string, any>;
        disableWatcher: boolean;
        currentData: Record<string, any>;

        constructor(disableWatcher?: boolean);
        load(lang: string): Promise<void>;

        loadFile(filePath: string, lang: string): Promise<Record<string, any>>;

        translate(key: string, lang: string): string;
    }
}
