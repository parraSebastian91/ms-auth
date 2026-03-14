export class ApiResponse<T> {
  constructor(
    public status: number,
    public message: string,
    public data?: T,
  ) {}
}
