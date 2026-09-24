import { formRegistroData } from "../../model/dataRegistro.model";

export interface IRegistroUseCase {
    ExecuteValidateField(field: string, value: string): Promise<{ available: boolean; message?: string }>;
    executeCreateRegistro(data: formRegistroData): Promise<{ success: boolean; message?: string }>;
    executeVerificarEmail(email: string, code: string): Promise<{ success: boolean; message?: string }>;
    executeResendOtp(email: string): Promise<{ success: boolean; message?: string }>;
}
    