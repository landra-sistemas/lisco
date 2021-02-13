export default class JsonResponse {
    constructor(success, data, message, total) {
        this.data = data;
        this.success = success;
        this.total = total;
        this.message = message || '';
    }

    toJson() {
        return (this);
    }
}
