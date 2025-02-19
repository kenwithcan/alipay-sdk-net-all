/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// PluginUseRelationInfo
    /// </summary>
    [DataContract(Name = "PluginUseRelationInfo")]
    public partial class PluginUseRelationInfo : IEquatable<PluginUseRelationInfo>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PluginUseRelationInfo" /> class.
        /// </summary>
        /// <param name="betaMemo">邀测驳回原因.</param>
        /// <param name="betaPluginVersion">邀测插件版本号.</param>
        /// <param name="betaQrCodeUrl">邀测二维码.</param>
        /// <param name="betaStatus">WAITCHECK-待确认;CHECKED-确认;REJECT-拒绝.</param>
        /// <param name="gmtActive">激活时间.</param>
        /// <param name="gmtCreate">订购时间.</param>
        /// <param name="gmtInvalid">插件失效时间.</param>
        /// <param name="miniAppId">应用ID.</param>
        /// <param name="pluginDeployVersion">插件构建版本.</param>
        /// <param name="pluginId">插件ID.</param>
        /// <param name="pluginStatus">插件状态，取值包括EXECUTING/WAIT_WORKING/WORKING/STOP_WORKING/WAIT_BUY.</param>
        /// <param name="pluginUseConfigInfoList">分端版本配置信息列表.</param>
        /// <param name="pluginVersion">插件版本.</param>
        /// <param name="runModeType">插件运行状态，取值包括ONLINE/TRIAL/REVIEW/DEBUG.</param>
        /// <param name="sourceFrom">渠道来源，取值包括SHOP_MINI/PLUGIN_DEBUG/PLUGIN_TRIAL/PLUGIN_AUDIT/GENERAL_SHOP_ID.</param>
        public PluginUseRelationInfo(string betaMemo = default(string), string betaPluginVersion = default(string), string betaQrCodeUrl = default(string), string betaStatus = default(string), string gmtActive = default(string), string gmtCreate = default(string), string gmtInvalid = default(string), string miniAppId = default(string), string pluginDeployVersion = default(string), string pluginId = default(string), string pluginStatus = default(string), List<PluginUseConfigInfo> pluginUseConfigInfoList = default(List<PluginUseConfigInfo>), string pluginVersion = default(string), string runModeType = default(string), string sourceFrom = default(string))
        {
            this.BetaMemo = betaMemo;
            this.BetaPluginVersion = betaPluginVersion;
            this.BetaQrCodeUrl = betaQrCodeUrl;
            this.BetaStatus = betaStatus;
            this.GmtActive = gmtActive;
            this.GmtCreate = gmtCreate;
            this.GmtInvalid = gmtInvalid;
            this.MiniAppId = miniAppId;
            this.PluginDeployVersion = pluginDeployVersion;
            this.PluginId = pluginId;
            this.PluginStatus = pluginStatus;
            this.PluginUseConfigInfoList = pluginUseConfigInfoList;
            this.PluginVersion = pluginVersion;
            this.RunModeType = runModeType;
            this.SourceFrom = sourceFrom;
        }

        /// <summary>
        /// 邀测驳回原因
        /// </summary>
        /// <value>邀测驳回原因</value>
        [DataMember(Name = "beta_memo", EmitDefaultValue = false)]
        public string BetaMemo { get; set; }

        /// <summary>
        /// 邀测插件版本号
        /// </summary>
        /// <value>邀测插件版本号</value>
        [DataMember(Name = "beta_plugin_version", EmitDefaultValue = false)]
        public string BetaPluginVersion { get; set; }

        /// <summary>
        /// 邀测二维码
        /// </summary>
        /// <value>邀测二维码</value>
        [DataMember(Name = "beta_qr_code_url", EmitDefaultValue = false)]
        public string BetaQrCodeUrl { get; set; }

        /// <summary>
        /// WAITCHECK-待确认;CHECKED-确认;REJECT-拒绝
        /// </summary>
        /// <value>WAITCHECK-待确认;CHECKED-确认;REJECT-拒绝</value>
        [DataMember(Name = "beta_status", EmitDefaultValue = false)]
        public string BetaStatus { get; set; }

        /// <summary>
        /// 激活时间
        /// </summary>
        /// <value>激活时间</value>
        [DataMember(Name = "gmt_active", EmitDefaultValue = false)]
        public string GmtActive { get; set; }

        /// <summary>
        /// 订购时间
        /// </summary>
        /// <value>订购时间</value>
        [DataMember(Name = "gmt_create", EmitDefaultValue = false)]
        public string GmtCreate { get; set; }

        /// <summary>
        /// 插件失效时间
        /// </summary>
        /// <value>插件失效时间</value>
        [DataMember(Name = "gmt_invalid", EmitDefaultValue = false)]
        public string GmtInvalid { get; set; }

        /// <summary>
        /// 应用ID
        /// </summary>
        /// <value>应用ID</value>
        [DataMember(Name = "mini_app_id", EmitDefaultValue = false)]
        public string MiniAppId { get; set; }

        /// <summary>
        /// 插件构建版本
        /// </summary>
        /// <value>插件构建版本</value>
        [DataMember(Name = "plugin_deploy_version", EmitDefaultValue = false)]
        public string PluginDeployVersion { get; set; }

        /// <summary>
        /// 插件ID
        /// </summary>
        /// <value>插件ID</value>
        [DataMember(Name = "plugin_id", EmitDefaultValue = false)]
        public string PluginId { get; set; }

        /// <summary>
        /// 插件状态，取值包括EXECUTING/WAIT_WORKING/WORKING/STOP_WORKING/WAIT_BUY
        /// </summary>
        /// <value>插件状态，取值包括EXECUTING/WAIT_WORKING/WORKING/STOP_WORKING/WAIT_BUY</value>
        [DataMember(Name = "plugin_status", EmitDefaultValue = false)]
        public string PluginStatus { get; set; }

        /// <summary>
        /// 分端版本配置信息列表
        /// </summary>
        /// <value>分端版本配置信息列表</value>
        [DataMember(Name = "plugin_use_config_info_list", EmitDefaultValue = false)]
        public List<PluginUseConfigInfo> PluginUseConfigInfoList { get; set; }

        /// <summary>
        /// 插件版本
        /// </summary>
        /// <value>插件版本</value>
        [DataMember(Name = "plugin_version", EmitDefaultValue = false)]
        public string PluginVersion { get; set; }

        /// <summary>
        /// 插件运行状态，取值包括ONLINE/TRIAL/REVIEW/DEBUG
        /// </summary>
        /// <value>插件运行状态，取值包括ONLINE/TRIAL/REVIEW/DEBUG</value>
        [DataMember(Name = "run_mode_type", EmitDefaultValue = false)]
        public string RunModeType { get; set; }

        /// <summary>
        /// 渠道来源，取值包括SHOP_MINI/PLUGIN_DEBUG/PLUGIN_TRIAL/PLUGIN_AUDIT/GENERAL_SHOP_ID
        /// </summary>
        /// <value>渠道来源，取值包括SHOP_MINI/PLUGIN_DEBUG/PLUGIN_TRIAL/PLUGIN_AUDIT/GENERAL_SHOP_ID</value>
        [DataMember(Name = "source_from", EmitDefaultValue = false)]
        public string SourceFrom { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class PluginUseRelationInfo {\n");
            sb.Append("  BetaMemo: ").Append(BetaMemo).Append("\n");
            sb.Append("  BetaPluginVersion: ").Append(BetaPluginVersion).Append("\n");
            sb.Append("  BetaQrCodeUrl: ").Append(BetaQrCodeUrl).Append("\n");
            sb.Append("  BetaStatus: ").Append(BetaStatus).Append("\n");
            sb.Append("  GmtActive: ").Append(GmtActive).Append("\n");
            sb.Append("  GmtCreate: ").Append(GmtCreate).Append("\n");
            sb.Append("  GmtInvalid: ").Append(GmtInvalid).Append("\n");
            sb.Append("  MiniAppId: ").Append(MiniAppId).Append("\n");
            sb.Append("  PluginDeployVersion: ").Append(PluginDeployVersion).Append("\n");
            sb.Append("  PluginId: ").Append(PluginId).Append("\n");
            sb.Append("  PluginStatus: ").Append(PluginStatus).Append("\n");
            sb.Append("  PluginUseConfigInfoList: ").Append(PluginUseConfigInfoList).Append("\n");
            sb.Append("  PluginVersion: ").Append(PluginVersion).Append("\n");
            sb.Append("  RunModeType: ").Append(RunModeType).Append("\n");
            sb.Append("  SourceFrom: ").Append(SourceFrom).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as PluginUseRelationInfo);
        }

        /// <summary>
        /// Returns true if PluginUseRelationInfo instances are equal
        /// </summary>
        /// <param name="input">Instance of PluginUseRelationInfo to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(PluginUseRelationInfo input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BetaMemo == input.BetaMemo ||
                    (this.BetaMemo != null &&
                    this.BetaMemo.Equals(input.BetaMemo))
                ) && 
                (
                    this.BetaPluginVersion == input.BetaPluginVersion ||
                    (this.BetaPluginVersion != null &&
                    this.BetaPluginVersion.Equals(input.BetaPluginVersion))
                ) && 
                (
                    this.BetaQrCodeUrl == input.BetaQrCodeUrl ||
                    (this.BetaQrCodeUrl != null &&
                    this.BetaQrCodeUrl.Equals(input.BetaQrCodeUrl))
                ) && 
                (
                    this.BetaStatus == input.BetaStatus ||
                    (this.BetaStatus != null &&
                    this.BetaStatus.Equals(input.BetaStatus))
                ) && 
                (
                    this.GmtActive == input.GmtActive ||
                    (this.GmtActive != null &&
                    this.GmtActive.Equals(input.GmtActive))
                ) && 
                (
                    this.GmtCreate == input.GmtCreate ||
                    (this.GmtCreate != null &&
                    this.GmtCreate.Equals(input.GmtCreate))
                ) && 
                (
                    this.GmtInvalid == input.GmtInvalid ||
                    (this.GmtInvalid != null &&
                    this.GmtInvalid.Equals(input.GmtInvalid))
                ) && 
                (
                    this.MiniAppId == input.MiniAppId ||
                    (this.MiniAppId != null &&
                    this.MiniAppId.Equals(input.MiniAppId))
                ) && 
                (
                    this.PluginDeployVersion == input.PluginDeployVersion ||
                    (this.PluginDeployVersion != null &&
                    this.PluginDeployVersion.Equals(input.PluginDeployVersion))
                ) && 
                (
                    this.PluginId == input.PluginId ||
                    (this.PluginId != null &&
                    this.PluginId.Equals(input.PluginId))
                ) && 
                (
                    this.PluginStatus == input.PluginStatus ||
                    (this.PluginStatus != null &&
                    this.PluginStatus.Equals(input.PluginStatus))
                ) && 
                (
                    this.PluginUseConfigInfoList == input.PluginUseConfigInfoList ||
                    this.PluginUseConfigInfoList != null &&
                    input.PluginUseConfigInfoList != null &&
                    this.PluginUseConfigInfoList.SequenceEqual(input.PluginUseConfigInfoList)
                ) && 
                (
                    this.PluginVersion == input.PluginVersion ||
                    (this.PluginVersion != null &&
                    this.PluginVersion.Equals(input.PluginVersion))
                ) && 
                (
                    this.RunModeType == input.RunModeType ||
                    (this.RunModeType != null &&
                    this.RunModeType.Equals(input.RunModeType))
                ) && 
                (
                    this.SourceFrom == input.SourceFrom ||
                    (this.SourceFrom != null &&
                    this.SourceFrom.Equals(input.SourceFrom))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.BetaMemo != null)
                {
                    hashCode = (hashCode * 59) + this.BetaMemo.GetHashCode();
                }
                if (this.BetaPluginVersion != null)
                {
                    hashCode = (hashCode * 59) + this.BetaPluginVersion.GetHashCode();
                }
                if (this.BetaQrCodeUrl != null)
                {
                    hashCode = (hashCode * 59) + this.BetaQrCodeUrl.GetHashCode();
                }
                if (this.BetaStatus != null)
                {
                    hashCode = (hashCode * 59) + this.BetaStatus.GetHashCode();
                }
                if (this.GmtActive != null)
                {
                    hashCode = (hashCode * 59) + this.GmtActive.GetHashCode();
                }
                if (this.GmtCreate != null)
                {
                    hashCode = (hashCode * 59) + this.GmtCreate.GetHashCode();
                }
                if (this.GmtInvalid != null)
                {
                    hashCode = (hashCode * 59) + this.GmtInvalid.GetHashCode();
                }
                if (this.MiniAppId != null)
                {
                    hashCode = (hashCode * 59) + this.MiniAppId.GetHashCode();
                }
                if (this.PluginDeployVersion != null)
                {
                    hashCode = (hashCode * 59) + this.PluginDeployVersion.GetHashCode();
                }
                if (this.PluginId != null)
                {
                    hashCode = (hashCode * 59) + this.PluginId.GetHashCode();
                }
                if (this.PluginStatus != null)
                {
                    hashCode = (hashCode * 59) + this.PluginStatus.GetHashCode();
                }
                if (this.PluginUseConfigInfoList != null)
                {
                    hashCode = (hashCode * 59) + this.PluginUseConfigInfoList.GetHashCode();
                }
                if (this.PluginVersion != null)
                {
                    hashCode = (hashCode * 59) + this.PluginVersion.GetHashCode();
                }
                if (this.RunModeType != null)
                {
                    hashCode = (hashCode * 59) + this.RunModeType.GetHashCode();
                }
                if (this.SourceFrom != null)
                {
                    hashCode = (hashCode * 59) + this.SourceFrom.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
